import org.apache.commons.math3.linear.*;
import org.apache.commons.math3.util.ArithmeticUtils;
import org.apache.commons.math3.util.Precision;

import java.time.chrono.IsoEra;
import java.util.ArrayList;
import java.util.Scanner;

public class HillCipher {

    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz";
    private static final int PADDING_VALUE = 23; // equivalent to X
    public static final int CIPHER_MODULO = 26;
    public static final double EPSILON = 10E-12;

    /**
     *
     * @param plaintext
     * @return
     */
    public static String removeGrammarAndWhitespace(String plaintext) {
        return plaintext.replaceAll("[\\p{Punct}\\s]", "").toLowerCase();
    }

    /**
     *
     * @param text
     * @param blockSize
     * @return
     */
    public static RealMatrix getMatrixFromText(String text, int blockSize) {

        // Cleaning up the input text so it only contains a String of alphabet characters
        text = removeGrammarAndWhitespace(text);

        // 24 / 5 = we need 5 outer blocks with 1 padding
        // 26 / 5 = we need 6 blocks with 4 padding... etc.
        // Thus outer matrix size is the ceiling of the diviison
        int numRows = (int) Math.ceil((double)(text.length()) / (blockSize));

        // creating the 2d array to hold the values of each character converted into a number
        double[][] data = new double[numRows][blockSize];

        // looping through every element of the plaintext so we can place it in our data array
        for (int i = 0; i < data.length * data[0].length; i++) {

            int currentRow = i % blockSize; // integer modulus gives us the current row
            int currentColumn = i / blockSize; // integer floor division gives us the column

            double nextDataValue = PADDING_VALUE;

            if (i < text.length()) {
                nextDataValue = ALPHABET.indexOf(text.charAt(i));
            }

            data[currentColumn][currentRow] = nextDataValue;

        }

        return MatrixUtils.createRealMatrix(data);

    }

    /**
     *
     * @param matrix
     * @return
     */
    public static RealMatrix getAdjointMatrix(RealMatrix matrix) {

        // Create a new matrix to store cofactors
        RealMatrix cofactorMatrix = new Array2DRowRealMatrix(matrix.getRowDimension(), matrix.getColumnDimension());

        // Calculate cofactors for each element

        for (int i = 0; i < matrix.getRowDimension(); i++) {

            for (int j = 0; j < matrix.getColumnDimension(); j++) {

                ArrayList<Integer> rowArrayList = new ArrayList<>();
                for (int k = 0; k < matrix.getRowDimension(); k++) {
                    rowArrayList.add(k);
                }
                rowArrayList.remove(i);

                int[] rowArray = new int[rowArrayList.size()];
                for (int k = 0; k < rowArray.length; k++) {
                    rowArray[k] = rowArrayList.get(k);
                }

                ArrayList<Integer> columnArrayList = new ArrayList<>();
                for (int k = 0; k < matrix.getColumnDimension(); k++) {
                    columnArrayList.add(k);
                }
                columnArrayList.remove(j);

                int[] columnArray = new int[columnArrayList.size()];
                for (int k = 0; k < columnArray.length; k++) {
                    columnArray[k] = columnArrayList.get(k);
                }

                RealMatrix submatrix = matrix.getSubMatrix(rowArray, columnArray); // Get submatrix

                EigenDecomposition decomposition = new EigenDecomposition(submatrix);
                cofactorMatrix.setEntry(i, j, Math.pow(-1, i + j) * decomposition.getDeterminant());

            }

        }



        // Get the adjoint (transpose of cofactor matrix)

        return cofactorMatrix.transpose();
    }

    /**
     *
     * @param x
     * @param modulo
     * @return
     */
    public static int getInverseModulo(int x, int modulo) {
        while (x < 0) {
            x += modulo;
        }

        x = x % modulo;

        // Simplest way to find inverse modulo: check all numbers up until the modulo
        for (int i = 1; i < modulo; i++) {
            if ((x * i) % modulo == 1) {
                return i;
            }
        }

        // If the number has no inverse modulo, return -1
        return -1;
    }

    /**
     *
     * @param matrix
     * @return
     * @throws IllegalArgumentException
     */
    public static int getInverseDeterminant(RealMatrix matrix) throws IllegalArgumentException {

        double determinant = new EigenDecomposition(matrix).getDeterminant();

        if (Precision.compareTo(determinant, (int) determinant, EPSILON) != 0) {
            // means the determinant is not an integer, which we cannot use
            throw new IllegalArgumentException("The determinant of your matrix is not an integer!");
        }

        return getInverseModulo((int) determinant, CIPHER_MODULO); // Inverse doesn't exist

    }

    /**
     *
     * @param keyText
     * @param keySize
     * @return
     * @throws IllegalArgumentException
     */
    public static boolean isValidKey(String keyText, int keySize) throws IllegalArgumentException{

        if (keySize * keySize != keyText.length()) {
            return false;
        }

        RealMatrix keyTextToMatrix = getMatrixFromText(keyText, keySize);

        double determinant = new EigenDecomposition(keyTextToMatrix).getDeterminant();

        if (Precision.compareTo(determinant, (int) determinant, EPSILON) != 0) {
            // means the determinant is not an integer, which we cannot use
            throw new IllegalArgumentException("The determinant of your matrix is not an integer!");
        }

        // We require that the GCD of the determinant and our modulo 26 must be zero
        return (ArithmeticUtils.gcd((int) determinant, CIPHER_MODULO) == 1);

    }

    /**
     *
     * @param plaintext
     * @param keyText
     * @param keySize
     * @return
     */
    public static String getEncryptedText(String plaintext, String keyText, int keySize) {
        RealMatrix plaintextMatrix = getMatrixFromText(plaintext, keySize);
        RealMatrix keyTextMatrix = getMatrixFromText(keyText, keySize);
        String ciphertext = "";
        for (int i = 0; i < plaintextMatrix.getRowDimension(); i++) {
            double[] currentPlaintextRow = plaintextMatrix.getRow(i);
            for (int j = 0; j < keyTextMatrix.getRowDimension(); j++) {
                double[] currentKeyColumn = keyTextMatrix.getColumn(j);

                RealVector v1 = new ArrayRealVector(currentPlaintextRow);
                RealVector v2 = new ArrayRealVector(currentKeyColumn);

                // Using the formula for the ciphertext
                ciphertext += ALPHABET.charAt(((int) (v1.dotProduct(v2)) % CIPHER_MODULO));
            }

        }

        return ciphertext;

    }

    public static RealMatrix getInverseKey(RealMatrix keyMatrix) throws IllegalArgumentException{
        int inverseDeterminant = getInverseDeterminant(keyMatrix);

        if (inverseDeterminant == -1) {
            throw new IllegalArgumentException("The determinant of your matrix does " +
                                               "not have a multiplicative inverse modulo 26.");
        }

        RealMatrix keyInverseMatrix = getAdjointMatrix(keyMatrix);

        for (int i = 0; i < keyMatrix.getRowDimension(); i++) {
            for (int j = 0; j < keyMatrix.getColumnDimension(); j++) {
                double newValue = inverseDeterminant * keyInverseMatrix.getEntry(i, j);

                while (newValue < 0) {
                    newValue += CIPHER_MODULO;
                }
                newValue = newValue % CIPHER_MODULO;

                newValue = Math.round(newValue);

                keyInverseMatrix.setEntry(i, j, newValue);

            }
        }

        return keyInverseMatrix;

    }

    public static String getDecryptedText(String ciphertext, String keyText, int keySize) {
        RealMatrix ciphertextMatrix = getMatrixFromText(ciphertext, keySize);
        RealMatrix keyTextInverseMatrix = getInverseKey(getMatrixFromText(keyText, keySize));
        String plaintext = "";
        for (int i = 0; i < ciphertextMatrix.getRowDimension(); i++) {
            double[] currentPlaintextRow = ciphertextMatrix.getRow(i);
            for (int j = 0; j < keyTextInverseMatrix.getRowDimension(); j++) {
                double[] currentKeyColumn = keyTextInverseMatrix.getColumn(j);

                RealVector v1 = new ArrayRealVector(currentPlaintextRow);
                RealVector v2 = new ArrayRealVector(currentKeyColumn);

                plaintext += ALPHABET.charAt(((int) (v1.dotProduct(v2)) % CIPHER_MODULO));
            }

        }

        return plaintext;

    }

    // STEP 0: from plaintext to matrix

    // STEP 1: need to get adjoint of matrix
    // STEP 2: need to get inverse determinant modulo 26
        // include checks if the inverse exists
    // STEP 3: inverse modulo 26 is the product of STEP 2 and STEP 1

    // optional methods: take a string and convert into key, checking validity
    // generating random key
    // generating random key that matches a word in the dictionary

    // STEP 4: method that takes in a key and encrypts message
        // requires submethod that breaks message into matrix

    // STEP 5: method that calculates the inverse of a key by calling
    // the methods used in STEP 3

    // Given key inverse and ciphertext, calculate the plaintext

    // Method that executes known plaintext attack?

    public static void main(String[] args) {

//        var matrix = getMatrixFromText("XQCHJAVRGPBT", 3);
//
//        String keyText = "BEAHLCAFB";
//        var keyMatrix = getMatrixFromText(keyText, 3);
//
//        String keyText1 = "ABBA";
//        var keyMatrix1 = getMatrixFromText(keyText1, 2);
//
//        String plaintext = "time to study!";
//        var plaintextMatrix = getMatrixFromText(plaintext, 3);
//
//        System.out.println(plaintextMatrix);
        /*
        19 8 12
        4 19 14
        18 19 20
        3 24 23
         */

        Scanner in = new Scanner(System.in);

        System.out.println("Enter your plaintext: ");

        String plaintext = in.nextLine();

//        String plaintext = "My favorite subject so far is linear algebra!";
//        System.out.println(plaintext);

        System.out.println("Enter your keytext:");

        String keyText = in.nextLine();

//        String keyText = "BEAHLCAFB";

        String encryptedText = getEncryptedText(plaintext, keyText, 3);
        System.out.println("Your encrypted text is: " + encryptedText);

        System.out.println("Your decrypted text is: " + getDecryptedText(encryptedText, keyText, 3));

    }


}
