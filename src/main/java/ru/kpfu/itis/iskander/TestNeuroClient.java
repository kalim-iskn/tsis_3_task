package ru.kpfu.itis.iskander;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

public class TestNeuroClient {

    /* хеш для подписи */
    public static final String digest = "1F4A121121123123189002BC";
    /* 16-ричное представление публичного ключа сервиса */
    public static String publicKey16 = "30819f300d06092a864886f70d010101050003818d0030818902818100ad62bd06dd78a4a94f8c095f6ad0cea5cc5bf1f35607e2cefc01e2f9d5584fdd94bd609a5e3c599c219b4613c30247b5165f4bf67fd1cf96d60a1082d65728afafe4eff5bea632227a3e9406afb5790515178535d4f39586f0f342626e2a8bcd379edfeb06e053cd704957c6384baa1fefcf26bb4d5e84e0428c95d34df1e1a10203010001";
    public static String privateKey16 = "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100ad62bd06dd78a4a94f8c095f6ad0cea5cc5bf1f35607e2cefc01e2f9d5584fdd94bd609a5e3c599c219b4613c30247b5165f4bf67fd1cf96d60a1082d65728afafe4eff5bea632227a3e9406afb5790515178535d4f39586f0f342626e2a8bcd379edfeb06e053cd704957c6384baa1fefcf26bb4d5e84e0428c95d34df1e1a10203010001028180227792641efab0a107b32ad9d0fe1956543da2e7609ec8b3a4dd2b25c7077b38ed2c885ba7880fb83de60414419bde6d5d392c7ca004316426c0716fd0f41a9e1d3f90e7699c2142545dea3d4a761531bbb065d680ff746099fd24da74034cb68521b839b0173532fb3bcf69b8edf7f6be716d48f3be2b6f54b7f6160fed11d1024100f96ca387151192fe7cc98ddfc5e413fb513c126af8f607e8a43c325295ad6ac732d5316614154a420c67bf567492fe674a48debcef6020d696afe3d9f95cd663024100b1f4ea702f5ddc15f7a2cbecd0714612c9655c7ddab1c17e4353d05344735e4bb35a83c5c982b332e0ccdf257b19e1a0781725710636ffb6fb2eef29dd99552b024100e49c32760955864942cee9fe843ebc21c91f2a3269e5f6f1c0367c593d5f295352c01cfad6c57cbe74e85273477dc337a0da916cd26a652eca0684ecb0a5eac90240780b1fce5795782e7563232ef79941ccd08088b8f93aa9acf3dbe90f1280c49e4a3987e4773fac8468b2aae0ccbeb3be1ce478445b0de4c7d97f5aa422311a0b0241008e7b80fd05bd4e18b07ed0259b49840c7920792cdb58356c5939c7967ddc3a4b11edb9530ac8ee4fe055c500b92da4594f0c9f601b6cd22a9ea267a88768ca98";

    /* алгоритм ключа сервиса */
    public static final String KEY_ALGORITHM = "RSA";
    /* алгоритм подписи, формируемой сервисом */
    public static final String SIGN_ALGORITHM = "SHA256withRSA";

    public static String weights = "";

    public static void main(String[] args) {
        getChain("1331a5b51ad36063ac9a1bae21c5598ae404397cc1c2c491a3ddd0157891db8d");
        sendBlock();
    }

    public static void sendBlock() {

        SignService service = new SignService();

        String prevHash = null;
        if (BlockChain.chain.size() > 0) {
            try {
                prevHash = new String(Hex.encode(service.getHash(BlockChain.chain.get(BlockChain.chain.size() - 1))));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }

        String dataStr = "{\"w11\":\"0.1\",\"w12\":\"0.1\",\"w21\":\"0.1\",\"w22\":\"0.1\",\"v11\":\"0.1\",\"v12\":\"0.1\",\"v13\":\"0.1\",\"v21\":\"0.1\",\"v22\":\"0.1\",\"v23\":\"0.1\",\"w1\":\"0.1\",\"w2\":\"0.1\",\"w3\":\"0.1\",\"e\":\"0.6778807714293326\",\"publickey\":\"" + publicKey16 + "\"}";
        try {

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Hex.decode(privateKey16.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey priKey = keyFactory.generatePrivate(keySpec);

            byte[] sign = service.generateRSAPSSSignature(priKey, "Калимуллин Искандер 11-902 Smart".getBytes());
            String signature = new String(Hex.encode(sign));
            System.out.println("SIGNATURE: " + signature);

            String block = "{\"prevhash\":\"" + prevHash + "\",\"data\":" + dataStr + ",\"signature\":\"" + signature + "\"}";
            System.out.println(block);

            URL url = new URL("http://89.108.115.118/nbc/newblock?block=" + URLEncoder.encode(block, "UTF-8"));

            HttpURLConnection con = (HttpURLConnection) url.openConnection();

            con.setRequestMethod("GET");

            int rcode = con.getResponseCode();

            if (rcode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));

                String response = reader.readLine();

                ObjectMapper mapper = new ObjectMapper();
                NewBlockResponse resp = mapper.readValue(response, NewBlockResponse.class);
                if (resp.getStatus() == 0) {
                    BlockModel newBlock = resp.getBlock();
                    System.out.println(newBlock);
                } else {
                    System.out.println(resp.getStatusString());
                }
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    // Запрос блокчейна
    public static void getChain(String hash) {
        try {
            //URL url = new URL("http://188.93.211.195/newblock?block=");
            URL url = new URL("http://89.108.115.118/nbc/chain" + (hash != null ? "?hash=" + hash : ""));

            HttpURLConnection con = (HttpURLConnection) url.openConnection();

            con.setRequestMethod("GET");

            int rcode = con.getResponseCode();
            System.out.println(con.getResponseCode());

            if (rcode == 200) {
                ObjectMapper mapper = new ObjectMapper();
                List<BlockModel> blockChain = mapper.readValue(con.getInputStream(), new TypeReference<List<BlockModel>>() {
                });

                if (blockChain != null) {
                    BlockChain.chain = blockChain;
                    BlockChain.chain.forEach(blockModel -> {
                        System.out.println(blockModel.toString());
                    });
                }

                System.out.println(publicKey16);
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean verify(String publicKeyHexStr, byte[] data, String signHexStr) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            Signature signature = Signature.getInstance(SIGN_ALGORITHM, "BC");

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Hex.decode(publicKeyHexStr));
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
            signature.initVerify(pubKey);

            signature.update(data);

            return signature.verify(Hex.decode(signHexStr));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}