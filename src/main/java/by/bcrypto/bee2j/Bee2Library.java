package by.bcrypto.bee2j;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;
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
    void beltECBStart(  // Инициализация шифрования в режиме ECB
        byte[] state,		/*!< [out] состояние */
        byte[] key,		    /*!< [in] ключ */
        long len			/*!< [in] длина ключа в октетах */
    );
    void beltECBStepE(  // Зашифрование фрагмента в режиме ECB
        byte[] buf,			/*!< [in,out] открытый текст / шифртекст */
        long count,		    /*!< [in] число октетов текста */
        byte[] state		/*!< [in,out] состояние */
    );
    void beltECBStepD(  // Расшифрование в режиме ECB
        byte[] buf,			/*!< [in,out] шифртекст / открытый текст */
        long count,		    /*!< [in] число октетов текста */
        byte[] state		/*!< [in,out] состояние */
    );
    long beltCBC_keep();
    void beltCBCStart(  // Инициализация шифрования в режиме CBC
        byte[] state,		/*!< [out] состояние */
        byte[] key,		    /*!< [in] ключ */
        long len,			/*!< [in] длина ключа в октетах */
        byte[] iv		    /*!< [in] синхропосылка */
    );
    void beltCBCStepE(  // Зашифрование в режиме CBC
        byte[] buf,			/*!< [in,out] открытый текст / шифртекст */
        long count,		    /*!< [in] число октетов текста */
        byte[] state		/*!< [in,out] состояние */
    );
    void beltCBCStepD(  // Расшифрование в режиме CBC
        byte[] buf,			/*!< [in,out] шифртекст / открытый текст */
        long count,		    /*!< [in] число октетов текста */
        byte[] state		/*!< [in,out] состояние */
    );

    int beltCBCEncr(byte[] dest, byte[] src, long count,
                    byte[] theta, long len, byte[] iv);
    int beltCBCDecr(byte[] dest, byte[] src, long count,
                    byte[] key, long len, byte[] iv);

    int beltHash(byte[] hash, byte[] src, long count);
    int bashHash(byte[] hash, long l, byte[] src, long count);
    int bignOidToDER(byte[] oid_der, LongByReference oid_len, String oid);
    int bignSign(
        byte[] sig,			    /*!< [out] подпись */
        BignParams params,	    /*!< [in] долговременные параметры */
        byte[] oid_der,			/*!< [in] идентификатор хэш-алгоритма */
        long oid_len,
        byte[] hash,			/*!< [in] хэш-значение */
        byte[] privkey,		    /*!< [in] личный ключ */
        IRngFunction rng,		/*!< [in] генератор случайных чисел */
        byte[] rng_state);
    int bignVerify(
        BignParams params,	    /*!< [in] долговременные параметры */
        byte[] oid_der,			/*!< [in] идентификатор хэш-алгоритма */
        long oid_len,
        byte[] hash,
        byte[] sig,			    /*!< [in] подпись */
        byte[] pubkey			/*!< [in] открытый ключ */
    );

    int bignPubkeyCalc(
        byte[] pubkey,			/*!< [out] открытый ключ */
        BignParams params,	    /*!< [in] долговременные параметры */
        byte[] privkey		    /*!< [in] личный ключ */
    );
    int bignKeyWrap(
        byte[] token,			/*!< [out] токен ключа */
        BignParams params,		/*!< [in] долговременные параметры */
        byte[] key,				/*!< [in] транспортируемый ключ */
        long len,				/*!< [in] длина ключа в октетах */
        byte[] header,			/*!< [in] заголовок ключа [16]*/
        byte[] pubkey,			/*!< [in] открытый ключ получателя */
        IRngFunction rng,		/*!< [in] генератор случайных чисел */
        Pointer rng_state		/*!< [in/out] состояние генератора */
    );

    int bignKeyUnwrap(
        byte[] key,				/*!< [out] ключ */
        BignParams params,		/*!< [in] долговременные параметры */
        byte[] token,			/*!< [in] токен ключа */
        long len,				/*!< [in] длина токена в октетах */
        byte[] header,			/*!< [in] заголовок ключа [16]*/
        byte[] privkey);	    /*!< [in] личный ключ получателя */

    int bpkiPrivkeyUnwrap(      // Разбор контейнера с личным ключом
        byte[] privkey,                 /*!< [out] личный ключ */
        LongByReference privkey_len,    /*!< [in] длина privkey */
        byte[] epki,                    /*!< [in] контейнер с личным ключом */
        long epki_len,                  /*!< [in] длина epki */
        byte[] pwd,                     /*!< [in] пароль */
        long pwd_len                    /*!< [in] длина pwd */		
    );

    int bpkiPrivkeyWrap(        //Создание контейнера с личным ключом
        byte[] epki,			    /*!< [out] контейнер с личным ключом */
        LongByReference epki_len,	/*!< [out] длина epki */
        byte[] privkey,	            /*!< [in] личный ключ */
        long privkey_len,		    /*!< [in] длина privkey */
        byte[] pwd,		            /*!< [in] пароль */
        long pwd_len,			    /*!< [in] длина pwd */
        byte[] salt,	            /*!< [in] синхропосылка ("соль") PBKDF2 */
        long iter				    /*!< [in] количество итераций в PBKDF2 */
    );

    // Модуль brng
    int brngCTR_keep();
    void brngCTRStart(byte[] state, byte[] theta, byte[] iv);
    void brngCTRStepR(byte[] buf, long count, byte[] state);
    void brngCTRStepG(byte[] iv,byte[] state);
    int brngCTRRand(byte[] res, long count, byte[] theta, byte[] iv);
    int beltMAC(byte[] mac, byte[] src, long count, byte[] theta, long len);

    // Модуль der
    long derTLDec(        // Декодирование тега и длины
        IntByReference tag,     /*!< [out] тег */
        LongByReference len,    /*!< [out] длина значения */
        Pointer der,		    /*!< [in] DER-код */
    	long count			    /*!< [in] длина der в октетах */
    );

    int derTSEQDecStart(    // Начать декодирование TSEQ
        DerAnchor anchor,		/*!< [out] якорь */
        Pointer der,			/*!< [in] DER-код */
        long count,				/*!< [in] длина der в октетах */
        int tag					/*!< [in] тег ( 0x30 )*/
    );

    int derTSEQDecStop(  // Завершить декодирование TSEQ
        Pointer der,		    /*!< [in] DER-код */
        DerAnchor anchor	    /*!< [in] якорь */
    );

    int derTBITDec(      // Декодирование TBIT
        byte[]  val,		    /*!< [out] строка битов */
        LongByReference len,    /*!< [out] длина val в битах */
        Pointer der,	        /*!< [in] DER-код */
        long count,		        /*!< [in] длина der в октетах */
        int tag				    /*!< [in] тег (0x03) */
    );

    int derOIDDec(      // Декодирование OID
        byte[] oid,			    /*!< [out] идентификатор */
        LongByReference len,	/*!< [out] длина идентификатора */
        Pointer der,	        /*!< [in] DER-код */
        long count		        /*!< [in] длина der в октетах */
    );
}
