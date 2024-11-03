import org.apache.commons.math3.linear.*;
import org.apache.commons.math3.util.ArithmeticUtils;
import org.apache.commons.math3.util.Precision;

import java.util.ArrayList;
import java.util.Scanner;

public class HillCipher {

    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz";
    private static final int PADDING_VALUE = 23; // equivalent to X
    public static final int CIPHER_MODULO = 26;
    public static final double EPSILON = 10E-12;

    /**
     * Converts a given plaintext into a String only containing alphabet characters
     * @param plaintext the given plaintext
     * @return the cleaned up version of the plaintext, with no whitespace or grammar
     */
    public static String removeGrammarAndWhitespace(String plaintext) {
        return plaintext.replaceAll("[\\p{Punct}\\s]", "").toLowerCase();
    }

    /**
     * Gets the matrix from a given text, where each character of the text
     * is converted into a numerical value and placed in the matrix
     * @param text the given text
     * @param blockSize the number of columns in the resulting matrix
     * @return the matrix
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
     * Gets the adjugate matrix from a given matrix
     * @param matrix the given matrix
     * @return the adjugate matrix
     */
    public static RealMatrix getAdjugateMatrix(RealMatrix matrix) {

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
     * Gets the inverse of a number given a modulo
     * @param x the number to find the inverse of
     * @param modulo the modulo
     * @return the multiplicative inverse
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
     * Gets the inverse of the determinant of a given matrix
     * @param matrix the given matrix
     * @return the inverse of the determinant of the matrix
     * @throws IllegalArgumentException if the determinant of the matrix
     *                                  is not an integer (which we cannot work with)
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
     * Checks if a given key text can be converted into
     * a valid matrix
     * @param keyText the text of the key
     * @param keySize the block size for the key matrix
     * @return true if the given text can be converted into a valid
     * key matrix, false otherwise
     */
    public static boolean isValidKey(String keyText, int keySize) {

        if (keySize * keySize != keyText.length()) {
            return false;
        }

        RealMatrix keyTextToMatrix = getMatrixFromText(keyText, keySize);

        double determinant = new EigenDecomposition(keyTextToMatrix).getDeterminant();

        if (Precision.compareTo(determinant, (int) determinant, EPSILON) != 0) {
            // means the determinant is not an integer, which we cannot use
            return false;
        }

        // We require that the GCD of the determinant and our modulo 26 must be zero
        return (ArithmeticUtils.gcd((int) determinant, CIPHER_MODULO) == 1);

    }

    /**
     * Gets the encrypted text given a plaintext, the key text, and the block size
     * @param plaintext the given plaintext
     * @param keyText the text of the key
     * @param keySize the block size
     * @return the ciphertext
     */
    public static String getCiphertext(String plaintext, String keyText, int keySize) {
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

    /**
     * Gets the inverse matrix of a given matrix representing the key
     * @param keyMatrix the given matrix representing the key
     * @return the inverse matrix of the key matrix
     * @throws IllegalArgumentException if the given matrix cannot
     *                                  be inverted modulo n
     */
    public static RealMatrix getInverseKey(RealMatrix keyMatrix) throws IllegalArgumentException{
        int inverseDeterminant = getInverseDeterminant(keyMatrix);

        if (inverseDeterminant == -1) {
            throw new IllegalArgumentException("The determinant of your matrix does " +
                                               "not have a multiplicative inverse modulo 26.");
        }

        RealMatrix keyInverseMatrix = getAdjugateMatrix(keyMatrix);

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

    /**
     * Gets the plaintext from a given ciphertext, the key text, and the block size
     * @param ciphertext the given ciphertext
     * @param keyText the text of the key
     * @param keySize the block size
     * @return the plaintext
     */
    public static String getPlaintext(String ciphertext, String keyText, int keySize) {
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

    public static void main(String[] args) {

        Scanner in = new Scanner(System.in);

        System.out.println("Enter your plaintext: ");

        String plaintext = in.nextLine();

//        String plaintext = "My favorite subject so far is linear algebra!";
//        System.out.println(plaintext);

        System.out.println("Enter your keytext:");

        String keyText = in.nextLine();

//        String keyText = "BEAHLCAFB";

        String encryptedText = getCiphertext(plaintext, keyText, 3);
        System.out.println("Your encrypted text is: " + encryptedText);

        System.out.println("Your decrypted text is: " + getPlaintext(encryptedText, keyText, 3));

    }


}
