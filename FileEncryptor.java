import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptor {

    private static class Util {

        public static String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        }

        // code for this method found as first answer on this link:
        // https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
        /* s must be an even-length string. */
        public static byte[] hexStringToByteArray(String s) throws StringIndexOutOfBoundsException {
            int len = s.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16));
            }
            return data;
        }

        private static boolean isValidKey(String algorithm, String key) {
            try {
                return VALID_KEY_LENGTHS.get(algorithm).contains(Util.hexStringToByteArray(key).length * 8);
            } catch(StringIndexOutOfBoundsException e) {
                return false;
            }
        }

        private static boolean isValidIV(String algorithm, String iv) {
            try {
                return VALID_IV_LENGTHS.get(algorithm) == (Util.hexStringToByteArray(iv).length * 8);
            } catch(StringIndexOutOfBoundsException e) {
                return false;
            }
        }

        public static int boolToInt(boolean b) {
            return b ? 1 : 0;
        }
    }

    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final Map<String, List<Integer>> VALID_KEY_LENGTHS = Map.of(
            "AES", List.of(128, 192, 256),
            "BLOWFISH", IntStream.rangeClosed(32, 448).boxed().collect(Collectors.toList())
    );

    private static final Map<String, Integer> VALID_IV_LENGTHS = Map.of(
            "AES", 128,
            "BLOWFISH", 64
    );

    private static final Map<String, String> CIPHERS = Map.of(
            "AES", "AES/CBC/PKCS5PADDING",
            "BLOWFISH", "Blowfish/CBC/PKCS5Padding"
    );

    private static String algorithm;
    private static int keyLength;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IOException {

        if (args[0].equalsIgnoreCase("INFO")) {
            provideInfo(args);
            System.exit(0);
        }

        // check that the first argument is 'enc' or 'dec' (case ignored)
        if (!args[0].toLowerCase().matches("enc|dec")) throw new RuntimeException("Invalid operation. Try enc or dec.");

        boolean encrypting = args[0].equalsIgnoreCase("enc"); // if false => decrypting

        boolean hadValidAlgorithm = true;
        if(args[1].toUpperCase().matches("AES|BLOWFISH")) {
            algorithm = args[1].toUpperCase();
        } else {
            hadValidAlgorithm = false;
            algorithm = "AES"; // default
        }

        int argDisp = Util.boolToInt(hadValidAlgorithm);

        boolean hadValidKeyLength = false;
        try {
            int parsedKeyLength = Integer.parseInt(args[1 + argDisp]);
            if(VALID_KEY_LENGTHS.get(algorithm).contains(parsedKeyLength)) { // check if key length is valid
                hadValidKeyLength = true;
                keyLength = parsedKeyLength;
            }
        } catch(NumberFormatException e) {}
        finally {
            if(!hadValidKeyLength) {
                keyLength = 128; // default
            }
        }

        argDisp += Util.boolToInt(hadValidKeyLength);

        SecureRandom sr = new SecureRandom();

        byte[] key, initVector;
        boolean hadValidKey = true, hadValidIV = true;

        if (encrypting) {
            if (Util.isValidKey(algorithm, args[1 + argDisp])) {
                key = Util.hexStringToByteArray(args[1 + argDisp]);
            } else {
                hadValidKey = false;
                key = new byte[keyLength / 8];
                sr.nextBytes(key);
                System.out.println("Random key: " + Util.bytesToHex(key));
            }

            if (Util.isValidIV(algorithm, args[2 + argDisp])) {
                initVector = Util.hexStringToByteArray(args[2 + argDisp]);
            } else {
                hadValidIV = false;
                initVector = new byte[algorithm.equals("AES")? 16 : 8];
                sr.nextBytes(initVector);
                System.out.println("initVector: " + Util.bytesToHex(initVector));
            }
        } else {
            algorithm = provideInfo(args); // using metadata

            if (!Util.isValidKey(algorithm, args[1 + argDisp])) throw new RuntimeException("Provide valid key");
            key = Util.hexStringToByteArray(args[1 + argDisp]);

            if (!Util.isValidIV(algorithm, args[2 + argDisp])) {
                File file = new File(System.getProperty("user.dir") + "/ciphertext.data"); // incorrect name
                if (file.exists()) {
                    hadValidIV = false;
                    Scanner scanner = new Scanner(file);

                    String token, iv = null;
                    while(scanner.hasNext()) {
                        token = scanner.next();
                        if(token.equals("initialisation_vector:")) {
                            iv = scanner.next();
                            break;
                        }
                    }

                    if (!Util.isValidIV(algorithm, iv)) throw new RuntimeException("Provide valid initialisation vector!");
                    initVector = Util.hexStringToByteArray(iv);

                } else {
                    throw new RuntimeException("Provide valid initialisation vector");
                }
            } else {
                initVector = Util.hexStringToByteArray(args[2 + argDisp]);
            }
        }

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, algorithm);
        Cipher cipher = Cipher.getInstance(CIPHERS.get(algorithm));
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        argDisp += (Util.boolToInt(hadValidKey) + Util.boolToInt(hadValidIV));

        final Path fromPath = getFilePath(args[1 + argDisp]);
        final Path toPath = getFilePath(args[2 + argDisp]);

        String fromFileName = args[1 + argDisp].replace(fromPath.toString() + "/", "");
        String toFileName = args[2 + argDisp].replace(toPath.toString() + "/", "");

        // note that we have already checked that this argument is "enc" or "dec" (on line 70)
        if (encrypting) { // enc
            // write data file which contains algorithm metadata and initialisation vector
            String fileType = // of data data file
                    ".data";
            try (Writer writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(System.getProperty("user.dir") +
                            "/ciphertext" + fileType), "utf-8"))) {
                writer.write("metadata\n{\n");
                writer.write("\talgorithm: " + algorithm + "\n");
                writer.write("\tcipher: " + CIPHERS.get(algorithm) + "\n");
                writer.write("\tkey_length: " + keyLength + "\n");
                writer.write("}\n\n");
                writer.write("initialisation_vector: " + Util.bytesToHex(initVector) + "\n");
            }

            final Path encryptedPath = encrypt(fromFileName, toFileName, cipher, fromPath, toPath);
            LOG.info("Encryption finished, saved at " + encryptedPath);
        } else { // dec
            final Path encryptedPath = Path.of(fromPath.toString() + "/" + fromFileName);
            final Path decryptedPath = decrypt(toFileName, iv, skeySpec, cipher, encryptedPath, toPath);
            LOG.info("Decryption complete, open " + decryptedPath);
        }
    }

    private static String provideInfo(String[] args) {
        // parse ciphertext.data and determine info
        File dataFile = new File("ciphertext" + ".data");
        try {
            Scanner scanner = new Scanner(dataFile);
            String algorithm, keyLength;
            while(!scanner.next().equals("algorithm:")) scanner.next();
            algorithm = scanner.next();
            while(!scanner.next().equals("key_length:")) scanner.next();
            keyLength = scanner.next();

            System.out.println(algorithm + " " + keyLength); // print algorithm

            return algorithm;

        } catch(FileNotFoundException e) {
            System.out.println("data file not found");
            return "AES"; // default
        }
    }

    private static Path getFilePath(String pathName) {
        String filePath = ""; // this assumes by default that the file path is the current directory
        try {
            filePath = pathName.substring(0, pathName.lastIndexOf("/")); // corrects if assumption is false
        } catch (StringIndexOutOfBoundsException e) {
        }
        return filePath.equals("") ? Path.of(System.getProperty("user.dir")) : Path.of(filePath);
    }

    private static Path encrypt(String plaintextName, String ciphertextName, Cipher cipher, Path fromFilePath, Path toPath) {
        final Path encryptedPath = toPath.resolve(ciphertextName);
        try (InputStream fin = new FileInputStream(fromFilePath.toString() + "/" + plaintextName);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        return encryptedPath;
    }

    private static Path decrypt(String decryptedFileName, IvParameterSpec iv, SecretKeySpec skeySpec, Cipher cipher, Path fromPath, Path toPath) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        final Path decryptedPath = toPath.resolve(decryptedFileName);
        try (InputStream encryptedData = Files.newInputStream(fromPath);
             CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
             OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        return decryptedPath;
    }
}