/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

// SunJSSE does not support dynamic system properties, no way to re-use
// system properties in samevm/agentvm mode.

/*
 * @test
 * @summary tls-unique channel binding and client Finished verify_data support
 * @library /javax/net/ssl/templates /test/lib
 * @build SSLEngineTemplate
 * @run main/othervm
 *      -Dsun.security.ssl.enableTlsUniqueChannelBinding=true
 *      TlsUniqueChannelBindingTest
 * @run main/othervm TlsUniqueChannelBindingTest DISABLED
 */

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;
import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import static jdk.test.lib.Asserts.*;

/**
 * Tests for the tls-unique channel binding (RFC 5929) exposed via
 * {@link ExtendedSSLSession#getTlsUniqueChannelBinding()} and the
 * client Finished verify_data via
 * {@link ExtendedSSLSession#getClientFinishedVerifyData()}.
 *
 * The test creates pairs of SSLEngines (client/server), performs
 * handshakes, and validates that both values are correct
 * for each scenario.
 */
public class TlsUniqueChannelBindingTest extends SSLEngineTemplate {

    private final String protocol;
    private final String ciphersuite;

    protected TlsUniqueChannelBindingTest(String protocol,
            String ciphersuite) throws Exception {
        super();
        this.protocol = protocol;
        this.ciphersuite = ciphersuite;
    }

    @Override
    protected SSLEngine configureClientEngine(SSLEngine clientEngine) {
        clientEngine.setUseClientMode(true);
        SSLParameters params = clientEngine.getSSLParameters();
        params.setProtocols(new String[] { protocol });
        params.setCipherSuites(new String[] { ciphersuite });
        clientEngine.setSSLParameters(params);
        return clientEngine;
    }

    @Override
    protected SSLEngine configureServerEngine(SSLEngine serverEngine) {
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(true);
        SSLParameters params = serverEngine.getSSLParameters();
        params.setProtocols(new String[] {
                "TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"
        });
        serverEngine.setSSLParameters(params);
        return serverEngine;
    }

    public static void main(String[] args) throws Exception {
        Security.setProperty("jdk.tls.disabledAlgorithms", "");

        if (args.length > 0 && "DISABLED".equals(args[0])) {
            runDisabledTests();
            return;
        }

        // TLS 1.2 full handshake — binding must be non-null and agree
        new TlsUniqueChannelBindingTest(
                "TLSv1.2",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").runFullHandshakeTest();
        new TlsUniqueChannelBindingTest(
                "TLSv1.2",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256").runFullHandshakeTest();

        // TLS 1.1 full handshake
        new TlsUniqueChannelBindingTest(
                "TLSv1.1",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA").runFullHandshakeTest();

        // TLS 1.0 full handshake
        new TlsUniqueChannelBindingTest(
                "TLSv1",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA").runFullHandshakeTest();

        // TLS 1.3 — tls-unique is not defined, must return null
        new TlsUniqueChannelBindingTest(
                "TLSv1.3",
                "TLS_AES_128_GCM_SHA256").runTls13NullTest();

        // Defensive copy — mutating the returned array must not affect
        // subsequent calls
        new TlsUniqueChannelBindingTest(
                "TLSv1.2",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").runDefensiveCopyTest();

        System.out.println("All tls-unique tests PASSED");
    }

    /**
     * When the feature is disabled (system property not set), the
     * binding must be null for all protocol versions.
     */
    private static void runDisabledTests() throws Exception {
        TlsUniqueChannelBindingTest test = new TlsUniqueChannelBindingTest(
                "TLSv1.2",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        test.runHandshake();

        ExtendedSSLSession clientSession =
                (ExtendedSSLSession) test.clientEngine.getSession();
        ExtendedSSLSession serverSession =
                (ExtendedSSLSession) test.serverEngine.getSession();

        assertNull(clientSession.getTlsUniqueChannelBinding(),
                "Disabled: client tls-unique must be null");
        assertNull(serverSession.getTlsUniqueChannelBinding(),
                "Disabled: server tls-unique must be null");
        assertNull(clientSession.getClientFinishedVerifyData(),
                "Disabled: client finished verify data must be null");
        assertNull(serverSession.getClientFinishedVerifyData(),
                "Disabled: server finished verify data must be null");
        log("Disabled feature test PASSED");

        System.out.println("All disabled tls-unique tests PASSED");
    }

    /**
     * Full handshake: both client and server should produce the same
     * non-null, non-empty tls-unique value.  For a full handshake,
     * tls-unique and client Finished verify_data are identical
     * (client's Finished is the first message).
     */
    private void runFullHandshakeTest() throws Exception {
        runHandshake();

        ExtendedSSLSession clientSession =
                (ExtendedSSLSession) clientEngine.getSession();
        ExtendedSSLSession serverSession =
                (ExtendedSSLSession) serverEngine.getSession();

        byte[] clientBinding = clientSession.getTlsUniqueChannelBinding();
        byte[] serverBinding = serverSession.getTlsUniqueChannelBinding();

        assertNotNull(clientBinding,
                protocol + ": client tls-unique should not be null");
        assertNotNull(serverBinding,
                protocol + ": server tls-unique should not be null");
        assertTrue(clientBinding.length > 0,
                protocol + ": tls-unique must not be empty");
        assertTrue(Arrays.equals(clientBinding, serverBinding),
                protocol + ": client and server tls-unique must match");

        // Client Finished verify_data must also agree between peers
        byte[] clientFin = clientSession.getClientFinishedVerifyData();
        byte[] serverFin = serverSession.getClientFinishedVerifyData();

        assertNotNull(clientFin,
                protocol + ": client finished verify data should not be null");
        assertNotNull(serverFin,
                protocol + ": server finished verify data should not be null");
        assertTrue(Arrays.equals(clientFin, serverFin),
                protocol + ": client and server finished verify data must match");

        // For a full handshake, tls-unique == client's Finished
        assertTrue(Arrays.equals(clientBinding, clientFin),
                protocol + ": full handshake: tls-unique must equal "
                + "client finished verify data");

        log(protocol + "/" + ciphersuite + " full handshake test PASSED");
    }

    /**
     * TLS 1.3: tls-unique is not defined and must return null.
     */
    private void runTls13NullTest() throws Exception {
        runHandshake();

        ExtendedSSLSession clientSession =
                (ExtendedSSLSession) clientEngine.getSession();
        ExtendedSSLSession serverSession =
                (ExtendedSSLSession) serverEngine.getSession();

        assertNull(clientSession.getTlsUniqueChannelBinding(),
                "TLS 1.3: client tls-unique must be null");
        assertNull(serverSession.getTlsUniqueChannelBinding(),
                "TLS 1.3: server tls-unique must be null");
        assertNull(clientSession.getClientFinishedVerifyData(),
                "TLS 1.3: client finished verify data must be null");
        assertNull(serverSession.getClientFinishedVerifyData(),
                "TLS 1.3: server finished verify data must be null");

        log("TLS 1.3 null test PASSED");
    }

    /**
     * Mutating the returned byte[] must not change the internally
     * stored value.  Tests both methods.
     */
    private void runDefensiveCopyTest() throws Exception {
        runHandshake();

        ExtendedSSLSession session =
                (ExtendedSSLSession) clientEngine.getSession();

        // tls-unique
        byte[] binding1 = session.getTlsUniqueChannelBinding();
        assertNotNull(binding1, "binding should not be null");

        byte[] original = binding1.clone();
        for (int i = 0; i < binding1.length; i++) {
            binding1[i] ^= 0xFF;
        }

        byte[] binding2 = session.getTlsUniqueChannelBinding();
        assertTrue(Arrays.equals(original, binding2),
                "getTlsUniqueChannelBinding must return a defensive copy");

        // client finished verify data
        byte[] fin1 = session.getClientFinishedVerifyData();
        assertNotNull(fin1, "client finished should not be null");

        byte[] finOriginal = fin1.clone();
        for (int i = 0; i < fin1.length; i++) {
            fin1[i] ^= 0xFF;
        }

        byte[] fin2 = session.getClientFinishedVerifyData();
        assertTrue(Arrays.equals(finOriginal, fin2),
                "getClientFinishedVerifyData must return a defensive copy");

        log("Defensive copy test PASSED");
    }

    /**
     * Drive the inherited SSLEngine pair through a complete handshake
     * and application data exchange.
     */
    private void runHandshake() throws Exception {
        boolean dataDone = false;
        while (isOpen(clientEngine) || isOpen(serverEngine)) {
            clientEngine.wrap(clientOut, cTOs);
            runDelegatedTasks(clientEngine);

            serverEngine.wrap(serverOut, sTOc);
            runDelegatedTasks(serverEngine);

            cTOs.flip();
            sTOc.flip();

            clientEngine.unwrap(sTOc, clientIn);
            runDelegatedTasks(clientEngine);

            serverEngine.unwrap(cTOs, serverIn);
            runDelegatedTasks(serverEngine);

            cTOs.compact();
            sTOc.compact();

            if (!dataDone && (clientOut.limit() == serverIn.position())
                    && (serverOut.limit() == clientIn.position())) {
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                clientEngine.closeOutbound();
                serverEngine.closeOutbound();
                dataDone = true;
            }
        }
    }

    private static void log(String message) {
        System.err.println(message);
    }
}
