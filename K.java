/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

import com.sun.security.auth.module.Krb5LoginModule;
import java.io.*;
import java.lang.reflect.Constructor;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.*;

import org.ietf.jgss.*;
import sun.security.krb5.EncryptedData;
import sun.security.krb5.EncryptionKey;
import sun.security.krb5.PrincipalName;
import sun.security.krb5.internal.ktab.KeyTabEntry;
import sun.security.util.DerValue;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Kerberos command line tool.
 */
public class K {

    private static Oid oidk;
    private static Oid oids;

    static {
        try {
            oidk = new Oid("1.2.840.113554.1.2.2");
            oids = new Oid("1.3.6.1.5.5.2");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static boolean isNative = false;
    private static boolean isDebug = false;
    private static int outputStyle = 0; // 0: auto, 1:color, 2:prefix
    private static boolean sm = false;
    private static boolean verbose = false;

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java <common option>* K <command> <option>*\n\n"
                    + "Common options:\n\n"
                    + " -n[=lib] uses native provider\n"
                    + " -d       turns on debug\n");
            System.out.println(q_help);
            System.out.println();
            System.out.println(p_help);
            System.out.println();
            System.out.println(w_help);
            System.out.println();
            System.out.println(d_help);
            System.out.println();
            System.out.println(c_help);
        } else {
            for (int i=0; i<args.length; i++) {
                if (args[i].equals("-d")) {
                    isDebug = true;
                    System.setProperty("sun.security.nativegss.debug", "true");
                    System.setProperty("sun.security.spnego.debug", "true");
                    System.setProperty("sun.security.krb5.debug", "true");
                    System.setProperty("sun.security.jgss.debug", "true");
                } else if (args[i].startsWith("-n")) {
                    isNative = true;
                    if (args[i].length() > 2) {
                        if (args[i].charAt(2) == '=') {
                            System.setProperty("sun.security.jgss.lib",
                                    args[i].substring(3));
                        } else {
                            throw new Exception("Unknown command " + args[i]);
                        }
                    }
                } else {
                    String command = args[i];
                    args = Arrays.copyOfRange(args, i + 1, args.length);
                    System.setProperty("sun.security.jgss.native",
                            Boolean.toString(isNative));
                    switch (command) {
                        case "q":
                            q(args);
                            break;
                        case "p":
                            p(args);
                            break;
                        case "w":
                            w(args);
                            break;
                        case "d":
                            d(args);
                            break;
                        case "c":
                            c(args);
                            break;
                        default:
                            throw new Exception("Unknown command " + command);
                    }
                    return;
                }
            }
        }
    }

    /**
     * Login to a KDC. user/pass, user/keytab, -/- (default ccache),
     * -/keytab (unbound), user/-- (default keytab), -/-- (unbound default keytab).
     * @param name username
     * @param pt password or keytab
     * @param init true if is initiator
     * @return the subject
     */
    private static Subject krb5login(String name, String pt, boolean init) throws LoginException {
        Subject subject = new Subject();

        if (isNative) {
            System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
            return subject;
        }

        Krb5LoginModule krb5 = new Krb5LoginModule();
        Map<String, String> map = new HashMap<String, String>();
        Map<String, Object> shared = new HashMap<String, Object>();

        map.put("doNotPrompt", "true");
        if (isDebug) {
            map.put("debug", "true");
        }
        if (init) {
            map.put("isInitiator", "true");
        } else {
            map.put("storeKey", "true");
            map.put("isInitiator", "false");
        }

        if (!name.equals("-")) {
            map.put("principal", name);
        }

        if (pt.equals("-")) {
            map.put("useTicketCache", "true");
        } else if (pt.equals("--")) {
            if (name.equals("-")) {
                map.put("principal", "*");
            }
            map.put("useKeyTab", "true");
        } else if (new File(pt).exists()) {
            if (name.equals("-")) {
                map.put("principal", "*");
            }
            map.put("useKeyTab", "true");
            map.put("keyTab", pt);
        } else {
            map.put("useFirstPass", "true");
            shared.put("javax.security.auth.login.name", name);
            shared.put("javax.security.auth.login.password", pt.toCharArray());
        }

        krb5.initialize(subject, null, shared, map);
        krb5.login();
        krb5.commit();
        return subject;
    }

    /**
     * Creates a GSSName, whose type depends on the service's format.
     * Could be name, name@REALM, name@host.
     */
    private static GSSName createName(GSSManager manager, String service)
            throws GSSException {
        if (service.indexOf('@') >= 0) {
            String second = service.substring(service.indexOf('@') + 1);
            if (second.toUpperCase().equals(second)) {  // Just a realm
                return manager.createName(service, GSSName.NT_USER_NAME);
            } else {
                return manager.createName(
                    service, GSSName.NT_HOSTBASED_SERVICE);
            }
        } else {
            return manager.createName(service, GSSName.NT_USER_NAME);
        }
    }

    static String q_help = "java K [-n] [-d] q <user> <key_or_tab> [<impersonate>] <peer> [-t] [-s] [-d] [-m]"
            + "\n\nGenerates an AP_REQ."
            + "\nFor example: java K q username password -m -t\n"
            + "\n user          my username, '-' uses the one in ccache"
            + "\n key_or_tab    password/keytab, '-' ccache, '--' default keytab"
            + "\n impersonate   impersonates this guy, if provided"
            + "\n peer          peer principal name"
            + "\n -talk         talks to peer"
            + "\n -spnego       uses SPNEGO, otherwise, krb5"
            + "\n -mutual       requests mutual"
            + "\n -deleg        requests cred deleg";

    public static void q(final String[] args) throws Exception {
        Subject subj = krb5login(args[0], args[1], true);;
        Subject.doAs(subj, new PrivilegedExceptionAction<Void>() {
            @Override
            public Void run() throws Exception {
                boolean deleg = false;
                boolean mutual = false;
                boolean talk = false;
                boolean useSPNEGO = false;
                String nextAlg = args[2];
                String nextNextAlg = null;
                String service, impersonate;
                for (int i=3; i<args.length; i++) {
                    String s = args[i];
                    if (s.equalsIgnoreCase("-s")) {
                        useSPNEGO = true;
                    } else if (s.equalsIgnoreCase("-d")) {
                        deleg = true;
                    } else if (s.equalsIgnoreCase("-t")) {
                        talk = true;
                    } else if (s.equalsIgnoreCase("-m")) {
                        mutual = true;
                    } else {
                        nextNextAlg = s;
                    }
                }
                if (nextNextAlg == null) {
                    impersonate = null;
                    service = nextAlg;
                } else {
                    impersonate = nextAlg;
                    service = nextNextAlg;
                }
                GSSManager manager = GSSManager.getInstance();
                GSSCredential cred = null;//manager.createCredential(GSSCredential.INITIATE_ONLY);
                if (impersonate != null) {
                    GSSName other = manager.createName(impersonate, GSSName.NT_USER_NAME);
                    Class c = Class.forName("com.sun.security.jgss.ExtendedGSSCredential");
                    cred = (GSSCredential)c.getMethod("impersonate", GSSName.class).invoke(cred, other);
                    //cred = ((ExtendedGSSCredential)cred).impersonate(other);
                }
                GSSContext context = manager.createContext(
                        createName(manager, service),
                        useSPNEGO ? oids : oidk,
                        cred,
                        GSSContext.DEFAULT_LIFETIME);
                if (deleg) context.requestCredDeleg(deleg);
                context.requestMutualAuth(mutual);
                byte[] token = new byte[0];
                while (!context.isEstablished()) {
                    token = context.initSecContext(token, 0, token.length);
                    if (token != null) {
                        writeToken("AP-REQ", token);
                    }
                    System.out.println("isEstablished/isProtReady: " + context.isEstablished() + "/" + context.isProtReady());
                    if (!context.isEstablished()) {
                        token = readToken("AP-REP");
                    }
                }
                statusContext(context);

                if (talk) {
                    talkOut(context, "Client to server");
                    talkIn(context);
                }

                context.dispose();
                if (cred != null) {
                    cred.dispose();
                }
                if (isDebug) print(subj);
                return null;
            }
        });
    }

    static String p_help = "java K [-n] [-d] p <user> <key_or_tab> [-t] [-s] [<backend> [-t] [-s] [-d] [-m]]\n"
            + "\nAccepts an AP_REQ and possibly creates another"
            + "\nFor example: java K p service keytab -t backend -t\n"
            + "\n user          my username, '-' uses ccache"
            + "\n key_or_tab    my password or keytab, '-' means ccache"
            + "\n -talk         talks with client"
            + "\n -spnego       uses SPNEGO, otherwise, krb5"
            + "\n backend       if exists, getDeleg and creates an AP-REQ to backend"
            + "\n -talk         talks with backend"
            + "\n -spnego       uses SPNEGO to backend, otherwise, krb5"
            + "\n -mutual       requests mutual to backend"
            + "\n -deleg        requests cred deleg to backend";

    public static void p(final String[] args) throws Exception {
        Subject subj = krb5login(args[0], args[1], false);
        Subject.doAs(subj, new PrivilegedExceptionAction<Void>() {
            @Override
            public Void run() throws Exception {
                String service = null;
                boolean deleg = false;
                boolean mutual = false;
                boolean talkToClient = false;
                boolean talkToBackend = false;
                boolean useSPNEGOToClient = false;
                boolean useSPNEGOToBackend = false;
                for (int i=2; i<args.length; i++) {
                    String s = args[i];
                    if (s.equalsIgnoreCase("-s")) {
                        if (service == null) useSPNEGOToClient = true;
                        else useSPNEGOToBackend = true;
                    } else if (s.equalsIgnoreCase("-d")) {
                        deleg = true;
                    } else if (s.equalsIgnoreCase("-t")) {
                        if (service == null) talkToClient = true;
                        else talkToBackend = true;
                    } else if (s.equalsIgnoreCase("-m")) {
                        mutual = true;
                    } else {
                        service = s;
                    }
                }
                GSSManager manager = GSSManager.getInstance();
                GSSContext context = manager.createContext(manager.createCredential(
                        args[0].equals("-") ? null : createName(manager, args[0]),
                        GSSCredential.INDEFINITE_LIFETIME,
                        useSPNEGOToClient ? oids : oidk,
                        GSSCredential.ACCEPT_ONLY));
                while (!context.isEstablished()) {
                    byte[] token = readToken("AP-REQ");
                    token = context.acceptSecContext(token, 0, token.length);
                    if (token != null) {
                        writeToken("AP-REP", token);
                    }
                    System.out.println("isEstablished/isProtReady: " + context.isEstablished() + "/" + context.isProtReady());
                }
                statusContext(context);

                if (talkToClient) {
                    talkIn(context);
                    talkOut(context, "Server to client");
                }

                if (service != null) {
                    GSSName serverName = createName(manager, service);
                    GSSCredential ded = context.getDelegCred();
                    System.out.println("Use delegated credentials as " + context.getSrcName());
                    context.dispose();
                    //System.out.println(ded.getRemainingInitLifetime(oid));
                    context = manager.createContext(
                            serverName,
                            useSPNEGOToBackend ? oids : oidk,
                            ded,
                            GSSContext.DEFAULT_LIFETIME);
                    context.requestMutualAuth(mutual);
                    if (deleg) {
                        context.requestCredDeleg(true);
                    }
                    byte[] token = new byte[0];
                    while (!context.isEstablished()) {
                        token = context.initSecContext(token, 0, token.length);
                        if (token != null) {
                            writeToken("AP-REQ", token);
                        }
                        System.out.println("isEstablished/isProtReady: " + context.isEstablished() + "/" + context.isProtReady());
                        if (!context.isEstablished()) {
                            token = readToken("AP-REP");
                        }
                    }
                    statusContext(context);
                    if (talkToBackend) {
                        talkOut(context, "Server to backend");
                        talkIn(context);
                    }
                    context.dispose();
                    if (ded != null) {
                        ded.dispose();
                    }
                } else {
                    context.dispose();
                }
                if (isDebug) print(subj);

                return null;
            }
        });
    }

    private static void statusContext(GSSContext context) throws GSSException {
        System.out.println("getSrcName/getTargName: " + context.getSrcName() + " -> " + context.getTargName());
        System.out.println("State: mutual" + (context.getMutualAuthState()?"+":"-")
                + " deleg" + (context.getCredDelegState()?"+":"-")
                + " anonymous" + (context.getAnonymityState()?"+":"-")
                + " conf" + (context.getConfState()?"+":"-")
                + " integ" + (context.getIntegState()?"+":"-")
                + " replay" + (context.getReplayDetState()?"+":"-")
                + " sequence" + (context.getSequenceDetState()?"+":"-"));
    }

    private static void talkOut(GSSContext context, String msg) throws Exception {
        byte[] data = msg.getBytes();
        byte[] data2 = data;
        MessageProp prop = new MessageProp(true);
        writeToken("wrap", context.wrap(data, 0, data.length, prop));
        writeToken("wrap", context.wrap(data2, 0, data2.length, prop));
        writeToken("wrap", context.wrap(data, 0, data.length, prop));
        writeToken("wrap", context.wrap(data2, 0, data2.length, prop));
    }

    private static void showProp(String label, MessageProp prop) {
        System.out.println(label + " priv" + (prop.getPrivacy()?"+":"-")
                + " dup" + (prop.isDuplicateToken()?"+":"-")
                + " gap" + (prop.isGapToken()?"+":"-")
                + " old" + (prop.isOldToken()?"+":"-")
                + " unseq" + (prop.isUnseqToken()?"+":"-"));
        // Wait until 8201627 is resolved.
        if (prop.isDuplicateToken() || prop.isGapToken()
                    || prop.isOldToken() || prop.isUnseqToken()) {
            throw new RuntimeException("Bad prop");
        }
    }

    private static void talkIn(GSSContext context) throws Exception {
        MessageProp prop;

        byte[] token1 = readToken("wrap");
        byte[] token2 = readToken("wrap");
        byte[] token3 = readToken("wrap");
        byte[] token4 = readToken("wrap");

        prop = new MessageProp(true);
        byte[] msg = context.unwrap(token1, 0, token1.length, prop);
        showProp("unwrap: \"" + new String(msg) + "\"", prop);

        prop = new MessageProp(true);
        byte[] msg2 = context.unwrap(token2, 0, token2.length, prop);
        showProp("unwrap: \"" + new String(msg2) + "\"", prop);

        prop = new MessageProp(true);
        byte[] msg3 = context.unwrap(token3, 0, token3.length, prop);
        showProp("unwrap: \"" + new String(msg) + "\"", prop);

        prop = new MessageProp(true);
        byte[] msg4 = context.unwrap(token4, 0, token4.length, prop);
        showProp("unwrap: \"" + new String(msg2) + "\"", prop);
    }

    static void writeToken(String name, byte[] token) throws Exception {
        String start = "-----START " + name + "-----";
        String end = "-----END " + name + "-----";
        System.out.println(start);
        System.out.println(Base64.getEncoder().encodeToString(token));
        System.out.println(end);
    }

    static byte[] readToken(String name) throws Exception {
        String start = "-----START " + name + "-----";
        String end = "-----END " + name + "-----";
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder sb = new StringBuilder();
        boolean in = false;
        System.out.println(">>> Waiting for " + name + "...");
        while (true) {
            String line = br.readLine();
            if (line == null) throw new Exception("No token to read");
            if (line.equals(start)) {
                in = true;
            } else if (in) {
                if (line.equals(end)) {
                    return Base64.getDecoder().decode(sb.toString());
                } else {
                    sb.append(line);
                }
            }
        }
    }

    private static void print(Subject s) {
        System.out.println(s.getPrincipals());
        for (Object o: s.getPrivateCredentials()) {
            if (o instanceof KerberosTicket) {
                KerberosTicket kt = (KerberosTicket)o;
                System.out.println("KerberosTicket: " + kt.getClient() + " -> "
                        + kt.getServer());
            } else if (o instanceof KerberosKey) {
                KerberosKey kk = (KerberosKey)o;
                System.out.println("KerberosKey: " + kk);
            } else {
                System.out.println(o.getClass());
            }
        }
    }

    ///////////////////////////////////////////////////////////////////

    static String w_help = "java K [-n] [-d] w [user] [pass] [scheme] <url>*"
            + "\n\nGrab a URL"
            + "\nFor example: java K w - - kerberos http://www.protected.com\n"
            + "\n user          my username"
            + "\n pass          my password"
            + "\n scheme        Negotiate or Kerberos or NTLM etc"
            + "\n url           URL";

    public static void w(String[] args) throws Exception {
        String HTTPLOG = "sun.net.www.protocol.http.HttpURLConnection";
        Logger.getLogger(HTTPLOG).setLevel(Level.ALL);
        Handler h = new ConsoleHandler();
        h.setLevel(Level.ALL);
        Logger.getLogger(HTTPLOG).addHandler(h);
        System.setProperty("http.maxRedirects", "10");
        String userName = null;
        String password = null;
        for (String arg : args) {
            if (arg.startsWith("http")) {
                System.err.println("\u001b[1;37;41m" + arg);
                System.err.println("\u001b[m\n");
                URL url = new URL(arg);
                InputStream ins = url.openConnection().getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(ins));
                String str;
                int pos = 0;
                while ((str = reader.readLine()) != null) {
                    if (pos++ > 10) {
                        System.out.print(".");
                    } else {
                        System.out.println(str);
                    }
                }
                System.out.println();
            } else if (arg.equalsIgnoreCase("negotiate")
                    || arg.equalsIgnoreCase("kerberos")) {
                System.setProperty("http.auth.preference", arg);
            } else if (userName == null) {
                userName = arg;
            } else if (password == null) {
                password = arg;
                Authenticator.setDefault(
                        new MyAuthenticator(userName, password.toCharArray()));
                userName = null;
                password = null;
            } else {
                throw new Exception("what is " + arg);
            }
        }
    }

    static class MyAuthenticator extends Authenticator {

        String user;
        char[] pass;

        public MyAuthenticator (String user, char[] pass) {
            this.user = user;
            this.pass = pass;
        }

        public PasswordAuthentication getPasswordAuthentication () {
            System.err.println("::::: PROVIDING " + getRequestingScheme() +
                    " PASSWORD AND USERNAME");
            return new PasswordAuthentication (user, pass);
        }
    }

    ///////////////////////////////////////////////////////////////////

    static String d_help = "java K d name pass etype\njava K d keytab"
            + "\n\nDecrypt a Kerberos EncryptedData."
            + "\nThe stdin includes EncryptedData in hex or raw\n"
            + "\n pname         Principal Name"
            + "\n pass          password"
            + "\n <usage>       Key usage number";

    public static void d(String[] args) throws Exception {
        byte[] cipher = System.in.readAllBytes();
        if (cipher[0] == '3' && cipher[1] == '0') {
            cipher = xeh(new String(cipher));
        }
        Constructor<EncryptedData> cons =
                EncryptedData.class.getDeclaredConstructor(DerValue.class);
        cons.setAccessible(true);
        EncryptedData d;
        try {
            d = cons.newInstance(new DerValue(cipher));
        } catch (Exception e) {
            System.out.println("Not full EncryptedData, maybe only cipher");
            d = null;
        }
        if (new File(args[0]).exists()) {
            // keytab
            sun.security.krb5.internal.ktab.KeyTab tab
                    = sun.security.krb5.internal.ktab.KeyTab.getInstance(args[0]);
            for (KeyTabEntry e: tab.getEntries()) {
                EncryptionKey k = e.getKey();
                EncryptedData d2 = d;
                if (d == null) {
                    d2 = new EncryptedData(k.getEType(), 0, cipher);
                }
                try {
                    System.err.println("Decrypted with " + e.getService());
                    System.out.write(dec0(k, d2, -1));
                    System.err.println("Decrypted with " + e.getService());
                    break;
                } catch (Exception e2) {
                    // next
                }
            }
        } else {
            System.err.println("\u001b[1;37;41muser: " + args[0]
                    + " pass: " + args[1]);
            System.err.println("\u001b[m\n");
            PrincipalName pn = new PrincipalName(args[0]);
            char[] password = args[1].toCharArray();
            int etype = Integer.valueOf(args[2]);
            int usage = args.length > 3 ? Integer.valueOf(args[3]) : -1;
            EncryptionKey k = EncryptionKey.acquireSecretKey(
                    password, pn.getSalt(), etype, null);
            if (d == null) {
                d = new EncryptedData(etype, 0, cipher);
            } else {
                if (d.getEType() != etype) {
                    System.err.println("\u001b[1;37;41md " + d.getEType());
                    System.err.println("\u001b[m\n");
                }
            }
            System.out.println(hex(k.asn1Encode()));
            System.out.write(dec0(k, d, usage));
        }
    }

    private static byte[] dec0(EncryptionKey k, EncryptedData d, int usage)
            throws Exception {
        if (usage >= 0) {
            return d.decrypt(k, usage);
        } else {
            for (int i=0; i<30; i++) {
                try {
                    byte[] out = d.decrypt(k, i);
                    System.out.println("=== detected keyusage: " + i + "===");
                    return out;
                } catch (Exception e) {
                    //
                }
            }
        }
        throw new Exception("No one works");
    }

    public static byte[] xeh(String in) {
        in = in.replaceAll("\\s", "");
        int len = in.length()/2;
        byte[] out = new byte[len];
        for (int i=0; i<len; i++) {
            out[i] = Byte.parseByte(in.substring(i*2, i*2+2), 16);
        }
        return out;
    }

    public static String hex(byte[] bs) {
        StringBuffer sb = new StringBuffer(bs.length * 2);
        for(byte b : bs) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    ///////////////////////////////////////////////////////////////////

    static String c_help = "java K c <option>* <command>+"
            + "\n\nChoreograph several commands talking to each other"
            + "\nFor example: java K c \"K -n q - - server -d\" \"K p server keytab backend\" -d 3000 \"K p backend keytab\"\n"
            + "\n -c            always uses color output"
            + "\n -p            always uses prefix output"
            + "\n -j <java>     uses this executable"
            + "\n -d <delay>    delay in milliseconds"
            + "\n -s            Run with security manager"
            + "\n -v            Display full data"
            + "\n command       Arguments of a java command";

    public static void c(String[] args) throws Exception {
        String java = System.getProperty("java.home") + "/bin/java";
        Files.write(Path.of("policy"), List.of(
                "grant {",
                "  permission java.security.AllPermission;",
                "};"
        ));
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "-c":
                    outputStyle = 1;
                    break;
                case "-p":
                    outputStyle = 2;
                    break;
                case "-s":
                    sm = true;
                    break;
                case "-j":
                    java = args[++i];
                    break;
                case "-d":
                    Thread.sleep(Long.parseLong(args[++i]));
                    break;
                case "-v":
                    verbose = true;
                    break;
                default:
                    run(java, arg);
            }
        }
    }

    static String inheritProperty(String k) {
        String v = System.getProperty(k);
        return v == null ? "" : (" -D" + k + "=" + v + " ");
    }

    static void run(String java, String s) throws Exception {
        if (sm) {
            s = "-Djava.security.manager -Djava.security.policy=policy " + s;
        }
        new Runner(java + " "
                + inheritProperty("java.class.path")
                + inheritProperty("java.security.krb5.conf")
                + inheritProperty("sun.security.jgss.lib")
                + inheritProperty("sun.security.krb5.acceptor.sequence.number.nonmutual")
                + " -ea -esa " + s);
    }

    static class Runner {
        Process p;
        Printer pt;
        Runner(String cmd) throws Exception {
            p = new ProcessBuilder(cmd.split(" +")).start();
            pt = Printer.get();
            new ReadThread(this).start();
            new ErrThread(this).start();
        }
    }

    static class ReadThread extends Thread {

        Runner r;
        static String WAIT_HEAD = ">>> Waiting for ";
        static String DATA_START = "-----START ";
        static String DATA_END = "-----END ";

        ReadThread(Runner r) { this.r = r; }

        @Override
        public void run() {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(r.p.getInputStream()));
            try {
                String block = null;
                String label = null;
                while (true) {
                    String s = br.readLine();
                    if (s == null) break;
                    r.pt.p(s.length() > 100 && !verbose ? (s.substring(0, 100) + "...") : s);
                    if (s.startsWith(WAIT_HEAD)) {
                        String name = s.substring(WAIT_HEAD.length(), s.length() - 3);
                        String data = Data.dataFor(name, r);
                        if (data != null) {
                            r.pt.p3(">>> See " + name);
                            r.p.getOutputStream().write(data.getBytes());
                            r.p.getOutputStream().flush();
                        } else {
                            Data.setRunner(name, r);
                        }
                    } else if (s.startsWith(DATA_START)) {
                        label = s.substring(DATA_START.length(), s.length() - 5);
                        block = s + "\n";
                    } else if (s.startsWith(DATA_END)) {
                        block += s + "\n";
                        Runner r2 = Data.runnerFor(label, r);
                        if (r2 != null) {
                            r2.pt.p3(">>> See " + label);
                            r2.p.getOutputStream().write(block.getBytes());
                            r2.p.getOutputStream().flush();
                        } else {
                            Data.setData(label, block, r);
                        }
                        label = null;
                    } else if (label != null) {
                        block += s + "\n";
                    }
                }
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }

    static class ErrThread extends Thread {

        Runner r;
        ErrThread(Runner r) { this.r = r; }

        @Override
        public void run() {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(r.p.getErrorStream()));
            try {
                while (true) {
                    String s = br.readLine();
                    if (s == null) break;
                    r.pt.p4(s);
                }
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }

    static class Data {

        // Proc waiting for data: label, null, r
        // Data waiting for proc: label, data, r
        static LinkedList<Object[]> data = new LinkedList<>();

        public synchronized static void setData(String label, String block, Runner r) {
            data.add(new Object[] {label, block, r});
        }

        public synchronized static Runner runnerFor(String label, Runner me) {
            Iterator<Object[]> iter = data.iterator();
            while (iter.hasNext()) {
                Object[] d = iter.next();
                if (d[0].equals(label) && d[1] == null && d[2] != me) {
                    iter.remove();
                    return (Runner) d[2];
                }
            }
            return null;
        }

        public synchronized static void setRunner(String name, Runner r) {
            data.add(new Object[] {name, null, r});
        }

        public synchronized static String dataFor(String name, Runner me) {
            Iterator<Object[]> iter = data.iterator();
            while (iter.hasNext()) {
                Object[] d = iter.next();
                if (d[0].equals(name) && d[1] != null && d[2] != me) {
                    iter.remove();
                    return (String) d[1];
                }
            }
            return null;
        }
    }

    static abstract class Printer {
        int c;
        int fore;
        static int now = 2;

        static Printer get() {
            int cc = now++;
            if (outputStyle == 0) {
                if (System.getenv("windir") != null) {
                    return new Mono(cc);
                } else {
                    return new Color(cc, cc == 7 ? 30 : 37);
                }
            } else if (outputStyle == 1) {
                return new Color(cc, cc == 7 ? 30 : 37);
            } else {
                return new Mono(cc);
            }
        }
        abstract void p(String s);
        abstract void p3(String s);
        abstract void p4(String s);

        static class Color extends Printer {
            Color(int c, int fore) {
                this.c = c;
                this.fore = fore;
            }

            void p(String s) {  // color
                System.out.println("\u001b[1;" + fore + ";4" + c + "m" + s + "\u001b[m");
            }

            void p3(String s) { // italic
                System.out.println("\u001b[1;3;" + fore + ";4" + c + "m" + s + "\u001b[m");
            }

            void p4(String s) { // underline
                System.out.println("\u001b[1;4;" + fore + ";4" + c + "m" + s + "\u001b[m");
            }
        }

        static class Mono extends Printer {
            Mono(int c) {
                this.c = c;
            }

            void p(String s) {  // color
                System.out.println(c + ": " + s);
            }

            void p3(String s) { // italic
                System.out.println(c + "> " + s);
            }

            void p4(String s) { // underline
                System.out.println(c + "< " + s);
            }
        }
    }
}
