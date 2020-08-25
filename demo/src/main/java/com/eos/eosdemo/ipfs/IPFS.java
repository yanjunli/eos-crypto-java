package com.eos.eosdemo.ipfs;

import io.ipfs.api.*;
import io.ipfs.multiaddr.MultiAddress;
import io.ipfs.multihash.Multihash;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 从 IPFS 原生 SDK 抽取的部分代码。可以根据自己的业务需要，自行封装。
 */
public class IPFS {

    public List<String> ObjectTemplates = Arrays.asList("unixfs-dir");
    public List<String> ObjectPatchTypes = Arrays.asList("add-link", "rm-link", "set-data", "append-data");
    private static final int DEFAULT_CONNECT_TIMEOUT_MILLIS = 10_000;
    private static final int DEFAULT_READ_TIMEOUT_MILLIS = 60_000;

    public final String host;
    public final int port;
    public final String protocol;
    private final String version;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;
    public final IPFSObject object = new IPFSObject();

    /**
     *  token
     */
    private static String token;

    public IPFS(MultiAddress addr) {
        this(addr.getHost(), addr.getTCPPort(), "/api/v0/", detectSSL(addr));
    }

    public IPFS(String host, int port, String version, boolean ssl) {
        this(host, port, version, DEFAULT_CONNECT_TIMEOUT_MILLIS, DEFAULT_READ_TIMEOUT_MILLIS, ssl);
    }

    public IPFS(String host, int port, String version, int connectTimeoutMillis, int readTimeoutMillis, boolean ssl) {
        if (connectTimeoutMillis < 0) throw new IllegalArgumentException("connect timeout must be zero or positive");
        if (readTimeoutMillis < 0) throw new IllegalArgumentException("read timeout must be zero or positive");
        this.host = host;
        this.port = port;
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;

        if (ssl) {
            this.protocol = "https";
        } else {
            this.protocol = "http";
        }
        this.version = version;
    }

    public void setToken(String token){
        this.token = token;
    }

    public String getToken(){
        return this.token;
    }

    public class IPFSObject {
        public List<MerkleNode> put(List<byte[]> data) throws IOException {
            Multipart m = new Multipart(protocol +"://" + host + ":" + port + version+"object/put?stream-channels=true", "UTF-8");
            for (byte[] f : data){
                m.addFilePart("file", Paths.get(""), new NamedStreamable.ByteArrayWrapper(f));
            }
            String res = m.finish();
            return JSONParser.parseStream(res).stream().map(x -> MerkleNode.fromJSON((Map<String, Object>) x)).collect(Collectors.toList());
        }

        public MerkleNode get(Multihash hash) throws IOException {
            Map json = retrieveMap("object/get?stream-channels=true&arg=" + hash);
            json.put("Hash", hash.toBase58());
            return MerkleNode.fromJSON(json);
        }
    }

    private Map retrieveMap(String path) throws IOException {
        return (Map)retrieveAndParse(path);
    }

    private Object retrieveAndParse(String path) throws IOException {
        byte[] res = retrieve(path);
        return JSONParser.parse(new String(res));
    }

    private byte[] retrieve(String path) throws IOException {
        URL target = new URL(protocol, host, port, version + path);
        return IPFS.get(target, connectTimeoutMillis, readTimeoutMillis);
    }

    private static byte[] get(URL target, int connectTimeoutMillis, int readTimeoutMillis) throws IOException {
        HttpURLConnection conn = configureConnection(target, "POST", connectTimeoutMillis, readTimeoutMillis);
        conn.setDoOutput(true);
        /* See IPFS commit for why this is a POST and not a GET https://github.com/ipfs/go-ipfs/pull/7097
           This commit upgrades go-ipfs-cmds and configures the commands HTTP API Handler
           to only allow POST/OPTIONS, disallowing GET and others in the handling of
           command requests in the IPFS HTTP API (where before every type of request
           method was handled, with GET/POST/PUT/PATCH being equivalent).
           The Read-Only commands that the HTTP API attaches to the gateway endpoint will
           additional handled GET as they did before (but stop handling PUT,DELETEs).
           By limiting the request types we address the possibility that a website
           accessed by a browser abuses the IPFS API by issuing GET requests to it which
           have no Origin or Referrer set, and are thus bypass CORS and CSRF protections.
           This is a breaking change for clients that relay on GET requests against the
           HTTP endpoint (usually :5001). Applications integrating on top of the
           gateway-read-only API should still work (including cross-domain access).
        */
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");

        try {
            OutputStream out = conn.getOutputStream();
            out.write(new byte[0]);
            out.flush();
            out.close();
            InputStream in = conn.getInputStream();
            ByteArrayOutputStream resp = new ByteArrayOutputStream();

            byte[] buf = new byte[4096];
            int r;
            while ((r = in.read(buf)) >= 0)
                resp.write(buf, 0, r);
            return resp.toByteArray();
        } catch (ConnectException e) {
            throw new RuntimeException("Couldn't connect to IPFS daemon at "+target+"\n Is IPFS running?");
        } catch (IOException e) {
            InputStream errorStream = conn.getErrorStream();
            String err = errorStream == null ? e.getMessage() : new String(readFully(errorStream));
            throw new RuntimeException("IOException contacting IPFS daemon.\n"+err+"\nTrailer: " + conn.getHeaderFields().get("Trailer"), e);
        }
    }

    private InputStream retrieveStream(String path) throws IOException {
        URL target = new URL(protocol, host, port, version + path);
        return IPFS.getStream(target, connectTimeoutMillis, readTimeoutMillis);
    }

    private static InputStream getStream(URL target, int connectTimeoutMillis, int readTimeoutMillis) throws IOException {
        HttpURLConnection conn = configureConnection(target, "POST", connectTimeoutMillis, readTimeoutMillis);
        return conn.getInputStream();
    }

    private static byte[] post(URL target, byte[] body, Map<String, String> headers, int connectTimeoutMillis, int readTimeoutMillis) throws IOException {
        HttpURLConnection conn = configureConnection(target, "POST", connectTimeoutMillis, readTimeoutMillis);
        for (String key: headers.keySet())
            conn.setRequestProperty(key, headers.get(key));
        conn.setDoOutput(true);
        OutputStream out = conn.getOutputStream();
        out.write(body);
        out.flush();
        out.close();

        InputStream in = conn.getInputStream();
        return readFully(in);
    }

    private static final byte[] readFully(InputStream in) {
        try {
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int r;
            while ((r=in.read(buf)) >= 0)
                resp.write(buf, 0, r);
            return resp.toByteArray();

        } catch(IOException ex) {
            throw new RuntimeException("Error reading InputStrean", ex);
        }
    }

    private static boolean detectSSL(MultiAddress multiaddress) {
        return multiaddress.toString().contains("/https");
    }

    private static HttpURLConnection configureConnection(URL target, String method, int connectTimeoutMillis, int readTimeoutMillis) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("Content-Type", "application/json");

        // 增加token 认证
        conn.setRequestProperty("Authorization","Bearer "+token);

        conn.setConnectTimeout(connectTimeoutMillis);
        conn.setReadTimeout(readTimeoutMillis);
        return conn;
    }
}
