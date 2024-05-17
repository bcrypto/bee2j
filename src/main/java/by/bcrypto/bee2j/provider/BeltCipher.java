package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.Bee2Library;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

//import com.sun.SunJCE;
//com.sun.crypto.provider.AESCipher

public class BeltCipher extends CipherSpi {

    public static final class BeltECB extends BeltCipher {
        public BeltECB() {
            super("ECB");
        }
    }

    public static final class BeltCBC extends BeltCipher {
        public BeltCBC() {
            super("CBC");
        }
        @Override
        protected byte[] initState(byte[] key, byte[] iv) {
            byte[] state = new byte[(int)bee2.beltCBC_keep()];
            bee2.beltCBCStart(state, key, key.length, iv);
            return state;
        };
        @Override
        protected byte[] updateState(byte[] data, int op, byte[] state) {
            byte[] result = data.clone();
            if(op == 1)
                bee2.beltCBCStepE(result, result.length, state);
            else if (op == 2)
                bee2.beltCBCStepD(result, result.length, state);
            return result;
        };
    }

    public static final class BeltCFB extends BeltCipher {
        public BeltCFB() {
            super("CFB");
        }
        @Override
        protected byte[] initState(byte[] key, byte[] iv) {
            byte[] state = new byte[(int)bee2.beltCFB_keep()];
            bee2.beltCFBStart(state, key, key.length, iv);
            return state;
        };
        @Override
        protected byte[] updateState(byte[] data, int op, byte[] state) {
            byte[] result = data.clone();
            if(op == 1)
                bee2.beltCFBStepE(result, result.length, state);
            else if (op == 2)
                bee2.beltCFBStepD(result, result.length, state);
            return result;
        };
    }

    public static final class BeltCTR extends BeltCipher {
        public BeltCTR() {
            super("CTR");
        }
        @Override
        protected byte[] initState(byte[] key, byte[] iv) {
            byte[] state = new byte[(int)bee2.beltCTR_keep()];
            bee2.beltCTRStart(state, key, key.length, iv);
            return state;
        };
        @Override
        protected byte[] updateState(byte[] data, int op, byte[] state) {
            byte[] result = data.clone();
            if(op == 1)
                bee2.beltCTRStepE(result, result.length, state);
            else if (op == 2)
                bee2.beltCTRStepE(result, result.length, state);
            return result;
        };
    }

    public static final class BeltMAC extends BeltCipher {
        public BeltMAC() {
            super("MAC");
        }
        @Override
        protected byte[] initState(byte[] key, byte[] iv) {
            byte[] state = new byte[(int)bee2.beltMAC_keep()];
            bee2.beltMACStart(state, key, key.length);
            return state;
        };
        @Override
        protected byte[] updateState(byte[] data, int op, byte[] state) {
            byte[] result = data.clone();
            bee2.beltMACStepA(result, result.length, state);
            return null;
        };
        @Override
        protected byte[] finishState(byte[] state) {
            byte[] mac = new byte[8];
            bee2.beltMACStepG(mac, state);
            return mac;
        };
    }

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
            default:
                throw new NoSuchAlgorithmException(
                    "Mode " + mode + " is not supported");
        }
    }

    /**
     * Sets the mode of this cipher to be MAC.
     */
    protected boolean modeIsMAC() {
        switch (this.mode) {
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
    };

    protected byte[] updateState(byte[] data, int op, byte[] state) {
        byte[] result = data.clone();
        if(op == 1)
            bee2.beltECBStepE(result, result.length, state);
        else if (op == 2)
            bee2.beltECBStepD(result, result.length, state);
        return result;
    };

    protected byte[] finishState(byte[] state) {
        return state;
    };

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
            if (this.mode == BELT_MODE.ECB)
                throw new InvalidAlgorithmParameterException("Parameter must be null for ECB mode");
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
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, are processed,
     * and the result is stored in a new buffer.
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
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, are processed,
     * and the result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code> inclusive.
     *
     * <p>If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown.
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
     * The data is encrypted or decrypted, depending on how this cipher was
     * initialized.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, and any input
     * bytes that may have been buffered during a previous <code>update</code>
     * operation, are processed, with padding (if requested) being applied.
     * If an AEAD mode such as GCM/CCM is being used, the authentication
     * tag is appended in the case of encryption, or verified in the
     * case of decryption.
     * The result is stored in a new buffer.
     *
     * <p>Upon finishing, this method resets this cipher object to the state
     * it was in when previously initialized via a call to
     * <code>engineInit</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>engineInit</code>) more data.
     *
     * <p>Note: if any exception is thrown, this cipher object may need to
     * be reset before it can be used again.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     * starts
     * @param inputLen the input length
     *
     * @return the new buffer with the result
     *
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size; or if this encryption algorithm is unable to
     * process the input data provided.
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     * @exception AEADBadTagException if this cipher is decrypting in an
     * AEAD mode (such as GCM/CCM), and the received authentication tag
     * does not match the calculated value
     */
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        byte[] src = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
        if(buffer != null) {
            buffer.write(input, inputOffset, inputLen);
            src = buffer.toByteArray();
        }
        if(src.length < blockSize && !this.modeIsMAC())
            throw new IllegalBlockSizeException("Data size should be at least 16" + this.mode);
        byte[] result = updateState(src, this.opmode, this.state);
        if(modeIsMAC())
            result = finishState(this.state);
        this.state = initState(this.secretKey, this.iv);
        this.buffer = null;
        return result;
    }

    /**
     * Encrypts or decrypts data in a single-part operation,
     * or finishes a multiple-part operation.
     * The data is encrypted or decrypted, depending on how this
     * {@code CipherSpi} object was initialized.
     *
     * <p>The first {@code inputLen} bytes in the {@code input}
     * buffer, starting at {@code inputOffset} inclusive, and any input
     * bytes that may have been buffered during a previous {@code update}
     * operation, are processed, with padding (if requested) being applied.
     * If an AEAD mode such as GCM or CCM is being used, the authentication
     * tag is appended in the case of encryption, or verified in the
     * case of decryption.
     * The result is stored in the {@code output} buffer, starting at
     * {@code outputOffset} inclusive.
     *
     * <p>Upon finishing, this method resets this {@code CipherSpi} object
     * to the state it was in when previously initialized via a call to
     * {@code engineInit}.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * {@code engineInit}) more data.
     *
     * <p>Note: if any exception is thrown, this {@code CipherSpi} object
     * may need to be reset before it can be used again.
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
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size; or if this encryption algorithm is unable to
     * process the input data provided
     * @throws ShortBufferException if the given output buffer is too small
     * to hold the result
     * @throws BadPaddingException if this {@code CipherSpi} object is in
     * decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
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
     * <p>
     * Calls to this method provide AAD to the cipher when operating in
     * modes such as AEAD (GCM/CCM).  If this cipher is operating in
     * either GCM or CCM mode, all AAD must be supplied before beginning
     * operations on the ciphertext (via the {@code update} and {@code
     * doFinal} methods).
     *
     * @param src the buffer containing the AAD
     * @param offset the offset in {@code src} where the AAD input starts
     * @param len the number of AAD bytes
     *
     * @throws IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized), does not accept AAD, or if
     * operating in either GCM or CCM mode and one of the {@code update}
     * methods has already been called for the active
     * encryption/decryption operation
     * @throws UnsupportedOperationException if this method
     * has not been overridden by an implementation
     *
     * @since 1.7
     */
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        throw new UnsupportedOperationException(
            "The underlying Cipher implementation "
            +  "does not support this method");
    }

    /**
     * Continues a multi-part update of the Additional Authentication
     * Data (AAD).
     * <p>
     * Calls to this method provide AAD to the cipher when operating in
     * modes such as AEAD (GCM/CCM).  If this cipher is operating in
     * either GCM or CCM mode, all AAD must be supplied before beginning
     * operations on the ciphertext (via the {@code update} and {@code
     * doFinal} methods).
     * <p>
     * All {@code src.remaining()} bytes starting at
     * {@code src.position()} are processed.
     * Upon return, the input buffer's position will be equal
     * to its limit; its limit will not have changed.
     *
     * @param src the buffer containing the AAD
     *
     * @throws IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized), does not accept AAD, or if
     * operating in either GCM or CCM mode and one of the {@code update}
     * methods has already been called for the active
     * encryption/decryption operation
     * @throws UnsupportedOperationException if this method
     * has not been overridden by an implementation
     *
     * @since 1.7
     */
    protected void engineUpdateAAD(ByteBuffer src) {
        throw new UnsupportedOperationException(
            "The underlying Cipher implementation "
            +  "does not support this method");
    }
}



