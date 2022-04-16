package com.company;

import mpi.MPI;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class Main {

    private static final int rootRank = 0;

    private static final int FILE_SIZE_BYTES = 536870912; //134217728;//

    private static final int SEND_KEY_TAG = 101;
    private static final int SEND_BYTES_TO_ENCODE_TAG = 102;
    private static final int SEND_BYTES_TO_DECODE_TAG = 103;
    private static final int SEND_ENCODED_BYTES = 104;
    private static final int SEND_DECODED_BYTES = 105;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        MPI.Init(args);
        int rank = MPI.COMM_WORLD.Rank();
        int size = MPI.COMM_WORLD.Size();
        int dest;
        boolean isEncryptionMode = true;
        boolean isPermanentSecretKey = true;


        if (rank == rootRank) {
            long timeStart =  System.currentTimeMillis();
            SecretKey secretKey = createDesSecretKey(isPermanentSecretKey);
            byte[] keyBytes = secretKey.getEncoded();

            byte[] fileToComputeArray = null;
            if (!isEncryptionMode)
                fileToComputeArray = getFileBytes("blob/encodedFileBlob");
            else
                fileToComputeArray = getFileBytes("blob/fileBlob");

            int bytesPerOneProcess = fileToComputeArray.length / (size-1) ;

            byte[] resultOfComputation = new byte[fileToComputeArray.length];
            //region1
            for (int destination = 1; destination < size; destination++) {

                byte[] sliceToSend = getElementsOfArrayFromIndex(fileToComputeArray, bytesPerOneProcess,
                        bytesPerOneProcess*(destination-1));
                //System.out.println("dest "+destination + " slice to Send capacity "+ sliceToSend.length);

                //Send key //Send //Isend
                MPI.COMM_WORLD.Send(keyBytes, 0, keyBytes.length, MPI.BYTE, destination, SEND_KEY_TAG);
                //send array slice
                MPI.COMM_WORLD.Send(sliceToSend, 0, sliceToSend.length, MPI.BYTE, destination, SEND_BYTES_TO_ENCODE_TAG);

            }
            for (int destination = 1; destination < size; destination++) {
                byte[] encodedBytes = new byte[bytesPerOneProcess];
                //get encoded array
                MPI.COMM_WORLD.Recv(encodedBytes, 0, bytesPerOneProcess, MPI.BYTE,
                        destination, SEND_ENCODED_BYTES);

                System.arraycopy(encodedBytes, 0, resultOfComputation,
                        bytesPerOneProcess*(destination-1), bytesPerOneProcess);
            }


                if (isEncryptionMode) {
                Files.write(Paths.get("blob/encodedFileBlob"), resultOfComputation);
            } else {
                Files.write(Paths.get("blob/decodedFileBlob"), resultOfComputation);
            }
            System.out.println("File was successfully saved!");
            System.out.println("Operating time: " + ((double)(System.currentTimeMillis() - timeStart))/1000 + " seconds");

            // Для того, чтобы удостовериться, что все отработало корректно
            if (!isEncryptionMode) {
                System.out.println("Result of comp hashcode:" + Arrays.hashCode(resultOfComputation));
                byte[] inputFileArray = getFileBytes("blob/fileBlob");
                System.out.println("input file hashcode:" + Arrays.hashCode(inputFileArray));
            }

        } else if (rank > 0) {
            byte[] keyBytes = new byte[8];
            byte[] slice = new byte[FILE_SIZE_BYTES / (size-1)];
            dest = 0;

            MPI.COMM_WORLD.Recv(keyBytes, 0, keyBytes.length, MPI.BYTE,
                    dest, SEND_KEY_TAG);
            SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "DES");

            MPI.COMM_WORLD.Recv(slice, 0, slice.length, MPI.BYTE,
                    dest, SEND_BYTES_TO_ENCODE_TAG);
            System.out.println("Rank" + rank + " takes slice array to encoding");


            byte[] resultOfEncryption = computeByDesAlgorithm(secretKey, slice, isEncryptionMode);

            MPI.COMM_WORLD.Send(resultOfEncryption, 0, resultOfEncryption.length, MPI.BYTE,
                    dest, SEND_ENCODED_BYTES);
            System.out.println("Result of encryption sent " +
                    "from rank:" + rank + " to root proccess");
        }
        MPI.Finalize();
    }

    private static byte[] getFileBytes(String path) {
        try {
            return Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    private static byte[] computeByDesAlgorithm(SecretKey secretKey, byte[] bytesToEncode, boolean isEncodingMode) {
        Cipher encoder = null;
        try {
            encoder = Cipher.getInstance("DES/ECB/NoPadding");
            if (isEncodingMode) {
                encoder.init(Cipher.ENCRYPT_MODE, secretKey);
            } else {
                encoder.init(Cipher.DECRYPT_MODE, secretKey);
            }
            return encoder.doFinal(bytesToEncode);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static byte[] getElementsOfArrayFromIndex(byte[] inputArray, int size, int fromIndex) {
        byte[] result = new byte[size];
        System.arraycopy(inputArray, fromIndex, result, 0, size);
        return result;
    }

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static SecretKey createDesSecretKey(boolean isPermanentSecretKey) throws NoSuchAlgorithmException {
        if (isPermanentSecretKey) {
            return new SecretKeySpec(new byte[]{0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x2, 0x1},
                    0, 8, "DES");
        } else {
            return KeyGenerator.getInstance("DES").generateKey();
        }
    }
}
