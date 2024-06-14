package by.bcrypto.bee2j;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

import by.bcrypto.bee2j.der.DerAnchor;

import java.nio.ByteBuffer;

public interface  Bee2Library extends Library{
    Bee2Library INSTANCE = Native.load("bee2", Bee2Library.class);

    interface IRngFunction extends Callback {
        void invoke(PointerByReference buf, int count, PointerByReference stack);
    }

    // тестовая функция brng. theta -- всегда одинаково
    class TestBrngFunc implements IRngFunction{

        public void invoke(PointerByReference buf, int count, PointerByReference state) {

            Bee2Library bee2 = Bee2Library.INSTANCE;

            Pointer p = bee2.beltH();
            byte[] theta = p.getByteArray(128,32);
            byte[] iv = state.getValue().getByteArray(0,32);
            byte[] res = buf.getValue().getByteArray(0,count);
            bee2.brngCTRRand(res, count, theta, iv);
            buf.getValue().write(0,res,0,count);
        }
    }

    class TestBrngForPK implements IRngFunction{

        public void invoke(PointerByReference buf, int count, PointerByReference state) {

            Bee2Library bee2 = Bee2Library.INSTANCE;

            Pointer p = bee2.beltH();
            byte[] theta = p.getByteArray(128,32);
            byte[] iv = p.getByteArray(192,32);
            byte[] res = p.getByteArray(0,96);
            bee2.brngCTRRand(res, count, theta, iv);
            buf.getPointer().write(0,res,0,count);
        }
    }

    class BrngFuncForPK implements IRngFunction {

        public void invoke(PointerByReference buf, int count, PointerByReference state) {

            Bee2Library bee2 = Bee2Library.INSTANCE;

            ByteBuffer buffer = ByteBuffer.allocate(count);
            buffer.putLong(System.currentTimeMillis());
            byte[] theta = buffer.array();
            byte[] iv = state.getPointer().getByteArray(0, count);
            byte[] res = buf.getPointer().getByteArray(0,count);
            bee2.brngCTRRand(res, count, theta, iv);
            buf.getPointer().write(0, res, 0, count);
        }
    }

    class BrngFunc implements IRngFunction {

        public void invoke(PointerByReference buf, int count, PointerByReference state) {

            Bee2Library bee2 = Bee2Library.INSTANCE;

            ByteBuffer buffer = ByteBuffer.allocate(count);
            buffer.putLong(System.currentTimeMillis());
            byte[] theta = buffer.array();
            byte[] iv = state.getPointer().getByteArray(0, count);
            byte[] res = buf.getPointer().getByteArray(0,count);
            bee2.brngCTRRand(res, count, theta, iv);
            buf.getPointer().write(0, res, 0, count);
        }
    }

    // нативные функции
    Pointer beltH();
    int bignParamsStd(BignParams bignParams, String name);
    int bignParamsVal(BignParams bignParams);
    int bignPubkeyVal(BignParams bignParams, byte[] pubKey);
    int bignKeypairGen(byte[] privKey, byte[] pubKey, BignParams bignParams,
                       IRngFunction rng, byte[] rng_state);

    int beltECBEncr(byte[] dest, byte[] src, long count,
                    byte[] theta, long len);
    int beltECBDecr(byte[] dest, byte[] src, long count,
                    byte[] theta, long len);

    long beltECB_keep();
    void beltECBStart(byte[] state, byte[] key, long len);
    void beltECBStepE(byte[] buf, long count, byte[] state);
    void beltECBStepD(byte[] buf, long count, byte[] state);
    long beltCBC_keep();
    void beltCBCStart(byte[] state,	byte[] key, long len, byte[] iv);
    void beltCBCStepE(byte[] buf, long count, byte[] state);
    void beltCBCStepD(byte[] buf, long count, byte[] state);

    int beltCBCEncr(byte[] dest, byte[] src, long count,
                    byte[] theta, long len, byte[] iv);
    int beltCBCDecr(byte[] dest, byte[] src, long count,
                    byte[] key, long len, byte[] iv);

    long beltCFB_keep();
    void beltCFBStart(byte[] state, byte[] key, long len, byte[] iv);
    void beltCFBStepE(byte[] buf, long count, byte[] state);
    void beltCFBStepD(byte[] buf, long count, byte[] state);

    long beltCTR_keep();
    void beltCTRStart(byte[] state,	byte[] key, long len, byte[] iv);
    void beltCTRStepE(byte[] buf, long count, byte[] state);

    long beltMAC_keep();
    void beltMACStart(byte[] state, byte[] key, long len);
    void beltMACStepA(byte[] buf, long count, byte[] state);
    void beltMACStepG(byte[] mac, byte[] state);

    long beltDWP_keep();
    void beltDWPStart(byte[] state, byte[] key, long len, byte[] iv);
    void beltDWPStepE(byte[] buf, long count, byte[] state);
    void beltDWPStepI(byte[] buf, long count, byte[] state);
    void beltDWPStepA(byte[] buf, long count, byte[] state);
    void beltDWPStepG(byte[] mac, byte[] state);
    int beltDWPStepV(byte[] mac, byte[] state);
    void beltDWPStepD(byte[] buf, long count, byte[] state);

    int beltHash(byte[] hash, byte[] src, long count);
    int bashHash(byte[] hash, long l, byte[] src, long count);
    int bignOidToDER(byte[] oid_der, LongByReference oid_len, String oid);
    int bignSign(byte[] sig, BignParams params, byte[] oid_der, long oid_len,
        byte[] hash, byte[] privkey, IRngFunction rng, byte[] rng_state);
    int bignVerify(BignParams params, byte[] oid_der, long oid_len,
        byte[] hash, byte[] sig, byte[] pubkey);

    int bignPubkeyCalc(byte[] pubkey, BignParams params, byte[] privkey);
    int bignKeyWrap(byte[] token, BignParams params, byte[] key, long len,
        byte[] header, byte[] pubkey, IRngFunction rng,	Pointer rng_state);
    int bignKeyUnwrap(byte[] key, BignParams params, byte[] token, long len,
        byte[] header, byte[] privkey);
    int bpkiPrivkeyUnwrap(byte[] privkey, LongByReference privkey_len,
        byte[] epki, long epki_len, byte[] pwd, long pwd_len);
    int bpkiPrivkeyWrap(byte[] epki, LongByReference epki_len, byte[] privkey,
        long privkey_len, byte[] pwd, long pwd_len, byte[] salt, long iter);

    // Модуль brng
    int brngCTR_keep();
    void brngCTRStart(byte[] state, byte[] theta, byte[] iv);
    void brngCTRStepR(byte[] buf, long count, byte[] state);
    void brngCTRStepG(byte[] iv,byte[] state);
    int brngCTRRand(byte[] res, long count, byte[] theta, byte[] iv);
    int beltMAC(byte[] mac, byte[] src, long count, byte[] theta, long len);

    // Модуль der
    long derTLDec(IntByReference tag, LongByReference len, Pointer der, 
        long count);
    int derTSEQDecStart(DerAnchor anchor, Pointer der, long count, int tag);
    int derTSEQDecStop(Pointer der, DerAnchor anchor);
    int derTBITDec(byte[] val, LongByReference len, Pointer der, long count, 
        int tag);
    int derOIDDec(byte[] oid, LongByReference len, Pointer der, long count);
}
