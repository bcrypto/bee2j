package by.bcrypto.bee2j.provider.cipher;

import by.bcrypto.bee2j.Bee2Library;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

public class BeltCipher extends CipherSpi {

    enum BELT_MODE {
        ECB,
        CBC,
        CFB,
        CTR,
        MAC,
        DWP,
        CHE,
        KWP
    }

    private int blockSize = 16;
    private int opmode;
    private BELT_MODE mode = BELT_MODE.ECB;
    private byte[] secretKey;
    private byte[] iv;
    protected Bee2Library bee2 = Bee2Library.INSTANCE;
    private byte[] state;
    private ByteArrayOutputStream buffer;

    /**
     * Creates an instance of Belt cipher in default ECB mode
     */
    public BeltCipher() {}

    /**
     * Creates an instance of Belt cipher 
     */
    protected BeltCipher(String mode) {
        try {
            engineSetMode(mode);
        } catch (GeneralSecurityException gse) {
            // internal error; re-throw as provider exception
            ProviderException pe =new ProviderException("Internal Error");
            pe.initCause(gse);
            throw pe;
        }
    }

    /**
     * Sets the mode of this cipher.
     *
     * @param mode the cipher mode
     *
     * @exception NoSuchAlgorithmException if the requested cipher mode does
     * not exist
     */
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        switch (mode) {
            case "ECB":
                this.mode = BELT_MODE.ECB;
                break;
            case "CBC":
                this.mode = BELT_MODE.CBC;
                break;
            case "CFB":
                this.mode = BELT_MODE.CFB;
                break;
            case "CTR":
                this.mode = BELT_MODE.CTR;
                break;
            case "MAC":
                this.mode = BELT_MODE.MAC;
                break;
            case "DWP":
                this.mode = BELT_MODE.DWP;
                break;
            default:
                throw new NoSuchAlgorithmException(
                    "Mode " + mode + " is not supported");
        }
    }

    /**
     * Check the mode of this cipher to be MAC.
     */
    protected boolean modeIsMAC() {
        switch (this.mode) {
            case MAC:
            case DWP:
                return true;
            default:
                return false;
        }
    }

    /**
     * Check the mode of this cipher to have no params.
     */
    protected boolean modeNoParams() {
        switch (this.mode) {
            case ECB:
            case MAC:
                return true;
            default:
                return false;
        }
    }

    protected byte[] initState(byte[] key, byte[] iv) {
        byte[] state = new byte[(int) bee2.beltECB_keep()];
        bee2.beltECBStart(state, key, key.length);
        return state;
    }

    protected byte[] updateState(byte[] data, int op, byte[] state) {
        byte[] result = data.clone();
        if(op == 1)
            bee2.beltECBStepE(result, result.length, state);
        else if (op == 2)
            bee2.beltECBStepD(result, result.length, state);
        return result;
    }

    protected byte[] finishState(byte[] state) {
        return state;
    }

    protected void updateAAD(byte[] data, byte[] state) {}

    /**
     * Sets the padding mechanism of this cipher.
     *
     * @param padding the padding mechanism
     *
     * @exception NoSuchPaddingException if the requested padding mechanism
     * does not exist
     */
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {

    }

    /**
     * Returns the block size (in bytes).
     *
     * @return the block size (in bytes)
     */
    protected int engineGetBlockSize() {
        return blockSize;
    }

    /**
     * Returns the length of output buffer for given input length. 
     *
     * @param inputLen the input length (in bytes)
     *
     * @return the required output buffer size (in bytes)
     */
    protected int engineGetOutputSize(int inputLen) {
        return inputLen;
    }

    /**
     * Returns the initialization vector (IV) in a new buffer.
     * 
     * @return the initialization vector in a new buffer, or null 
     */
    protected byte[] engineGetIV() {
        return this.iv.clone();
    }

    /**
     * Returns the parameters used with this cipher.
     *
     * <p>The returned parameters may be the same that were used to initialize
     * this cipher, or may contain a combination of default and random
     * parameter values used by the underlying cipher implementation if this
     * cipher requires algorithm parameters but was not initialized with any.
     *
     * @return the parameters used with this cipher, or null if this cipher
     * does not use any parameters.
     */
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

       /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     * @param opmode the operation mode of this cipher (this is one of
     * the following:
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     *
     * @exception InvalidKeyException if the given key is inappropriate 
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this cipher
     * @throws UnsupportedOperationException if {@code opmode} is
     * {@code WRAP_MODE} or {@code UNWRAP_MODE} is not implemented
     * by the cipher.
     */
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;
        this.secretKey = key.getEncoded();
        if(algorithmParameterSpec != null) {
            if(algorithmParameterSpec instanceof IvParameterSpec) {
                IvParameterSpec spec = (IvParameterSpec) algorithmParameterSpec;
                this.iv = spec.getIV();
            }    
        }
        this.state = initState(this.secretKey, this.iv);
        this.buffer = null;
    }

    /**
     * Initializes this cipher with a key and a source of randomness.
     *
     * @param opmode the operation mode of this cipher 
     * @param key the encryption key
     * @param random the source of randomness
     *
     * @exception InvalidKeyException if the given key is inappropriate 
     * @throws UnsupportedOperationException if {@code opmode} is
     * {@code WRAP_MODE} or {@code UNWRAP_MODE} is not implemented
     * by the cipher.
     */
    protected void engineInit(int opmode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        try {
            this.engineInit(opmode, key, (AlgorithmParameterSpec)null, secureRandom);
         } catch (InvalidAlgorithmParameterException err) {
            throw new InvalidKeyException(err.getMessage());
         }
    }

    /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     *
     * @param opmode the operation mode of this cipher 
     * @param key the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this cipher,
     * or if this cipher requires
     * algorithm parameters and <code>params</code> is null.
     * @throws UnsupportedOperationException if {@code opmode} is
     * {@code WRAP_MODE} or {@code UNWRAP_MODE} is not implemented
     * by the cipher.
     */
    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        String paramType = null;
        if (algorithmParameters != null) {
            if (modeNoParams())
                throw new InvalidAlgorithmParameterException("Parameter must be null for " + this.mode);
            try {
                 paramType = "IV";
                 spec = algorithmParameters.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException err) {
                throw new InvalidAlgorithmParameterException("Wrong parameter type: " + paramType + " expected");
            }
        }
        this.engineInit(opmode, key, spec, secureRandom);
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     * starts
     * @param inputLen the input length (if length is not divided to blockSize,
     * this block and all following will be buffered and result will be returned 
     * in engineDoFinal function)
     *
     * @return the new buffer with the result, or null if the underlying
     * cipher is a block cipher and the input data is too short to result in a
     * new block.
     */
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if(buffer == null) {
            if(inputLen % blockSize == 0)
                return updateState(Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen), 
                    this.opmode, this.state);
            else
                buffer = new ByteArrayOutputStream();
        }
        buffer.write(input, inputOffset, inputLen);
        return null;
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     * starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result
     * is stored
     *
     * @return the number of bytes stored in <code>output</code>
     *
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the result
     */
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        byte[] chunk = engineUpdate(input, inputOffset, inputLen); 
        if(chunk == null)
            return 0;
        if(output.length < chunk.length)
            throw new ShortBufferException();
        System.arraycopy(chunk, 0, output, outputOffset, chunk.length);
        return chunk.length;
    }

    /**
     * Encrypts or decrypts data in a single-part operation,
     * or finishes a multiple-part operation.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     * starts
     * @param inputLen the input length
     *
     * @return the new buffer with the result
     *
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     * and the total input length of the data processed by this cipher 
     * is less than block size
     * @exception AEADBadTagException if this cipher is decrypting in an
     * AEAD mode (such as GCM/CCM), and the received authentication tag
     * does not match the calculated value
     */
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        byte[] src = null;
        if(inputLen > 0 && input != null) {
            src = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
        }
        if(buffer != null) {
            if(input != null)
                buffer.write(input, inputOffset, inputLen);
            src = buffer.toByteArray();
        }
        if(!this.modeIsMAC() && src.length < blockSize)
            throw new IllegalBlockSizeException("Data size should be at least 16");
        byte[] result = null;  
        if(src != null)
            result = updateState(src, this.opmode, this.state);
        if(modeIsMAC())
            result = finishState(this.state);
        this.state = initState(this.secretKey, this.iv);
        this.buffer = null;
        return result;
    }

    /**
     * Encrypts or decrypts data in a single-part operation,
     * or finishes a multiple-part operation.
     *
     * @param input the input buffer
     * @param inputOffset the offset in {@code input} where the input
     * starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in {@code output} where the result
     * is stored
     *
     * @return the number of bytes stored in {@code output}
     *
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     * and the total input length of the data processed by this cipher 
     * is less than block size
     * @throws ShortBufferException if the given output buffer is too small
     * to hold the result
     * @throws AEADBadTagException if this {@code CipherSpi} object is
     * decrypting in an AEAD mode (such as GCM or CCM), and the received
     * authentication tag does not match the calculated value
     */
    protected int engineDoFinal(byte[] input, int inputOffset,
                                         int inputLen, byte[] output,
                                         int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if(output.length - outputOffset < result.length)
            throw new ShortBufferException();
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }


    /**
     * Wrap a key.
     *
     * <p>This concrete method has been added to this previously-defined
     * abstract class. (For backwards compatibility, it cannot be abstract.)
     * It may be overridden by a provider to wrap a key.
     * Such an override is expected to throw an IllegalBlockSizeException or
     * InvalidKeyException (under the specified circumstances),
     * if the given key cannot be wrapped.
     * If this method is not overridden, it always throws an
     * UnsupportedOperationException.
     *
     * @param key the key to be wrapped.
     *
     * @return the wrapped key.
     *
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested, and the length of the encoding of the
     * key to be wrapped is not a multiple of the block size.
     *
     * @exception InvalidKeyException if it is impossible or unsafe to
     * wrap the key with this cipher (e.g., a hardware protected key is
     * being passed to a software-only cipher).
     *
     * @throws UnsupportedOperationException if this method is not supported.
     */
    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Unwrap a previously wrapped key.
     *
     * <p>This concrete method has been added to this previously-defined
     * abstract class. (For backwards compatibility, it cannot be abstract.)
     * It may be overridden by a provider to unwrap a previously wrapped key.
     * Such an override is expected to throw an InvalidKeyException if
     * the given wrapped key cannot be unwrapped.
     * If this method is not overridden, it always throws an
     * UnsupportedOperationException.
     *
     * @param wrappedKey the key to be unwrapped.
     *
     * @param wrappedKeyAlgorithm the algorithm associated with the wrapped
     * key.
     *
     * @param wrappedKeyType the type of the wrapped key. This is one of
     * <code>SECRET_KEY</code>, <code>PRIVATE_KEY</code>, or
     * <code>PUBLIC_KEY</code>.
     *
     * @return the unwrapped key.
     *
     * @exception NoSuchAlgorithmException if no installed providers
     * can create keys of type <code>wrappedKeyType</code> for the
     * <code>wrappedKeyAlgorithm</code>.
     *
     * @exception InvalidKeyException if <code>wrappedKey</code> does not
     * represent a wrapped key of type <code>wrappedKeyType</code> for
     * the <code>wrappedKeyAlgorithm</code>.
     *
     * @throws UnsupportedOperationException if this method is not supported.
     */
    protected Key engineUnwrap(byte[] wrappedKey,
                               String wrappedKeyAlgorithm,
                               int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns the key size of the given key object in bits.
     * @param key the key object.
     * @return the key size of the given key object.
     * @exception InvalidKeyException if <code>key</code> is invalid.
     */
    protected int engineGetKeySize(Key key) throws InvalidKeyException {   
        if(key == null)
            throw new InvalidKeyException("Key is null.");
        return key.getEncoded().length * 8;
    }

    /**
     * Continues a multi-part update of the Additional Authentication
     * Data (AAD), using a subset of the provided buffer.
     *
     * @param src the buffer containing the AAD
     * @param offset the offset in {@code src} where the AAD input starts
     * @param len the number of AAD bytes
     *
     * @throws IllegalStateException if this cipher is in a wrong mode
     */
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        switch (this.mode) {
            case DWP:
                updateAAD(Arrays.copyOfRange(src, offset, offset + len), this.state);
                break;
            default:
                throw new IllegalStateException(
                    "Impossible operation for selected mode");
        }
    }

    /**
     * Continues a update of the Additional Authentication Data (AAD).
     *
     * @param src the buffer containing the AAD
     *
     * @throws IllegalStateException  cipher is in a wrong mode
     */
    protected void engineUpdateAAD(ByteBuffer src) {
        byte[] data = src.array();
        engineUpdateAAD(data, 0, data.length);
    }
}



