
package by.bcrypto.bee2j.provider;

import by.bcrypto.bee2j.Bee2Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.*;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class BrngSecureRandom extends SecureRandom {

    byte[] state = new byte[32];

    private Bee2Library.IRngFunction _rng = new Bee2Library.BrngFunc();

    public void engineNextBytes(byte[] bytes) {
        Pointer buf = new Memory(bytes.length);
        buf.write(0, bytes, 0, bytes.length);

        Pointer statePointer = new Memory(state.length);
        statePointer.write(0, state, 0, state.length);
        PointerByReference bufPointerByReference = new PointerByReference(buf);
        PointerByReference statePointerByReference = new PointerByReference(statePointer);
        _rng.invoke(bufPointerByReference, bytes.length, statePointerByReference);
        System.arraycopy(bufPointerByReference.getValue().getByteArray(0,bytes.length),0,bytes,0,bytes.length);
    }

    public Bee2Library.IRngFunction getRng()
    {
        return _rng;
    }
    public void setRng(Bee2Library.IRngFunction rng)
    {
        _rng = rng;
    }
    public byte[] engineGenerateSeed(int numBytes) {
        ByteBuffer buffer = ByteBuffer.allocate(numBytes);
        buffer.putLong(System.currentTimeMillis());

        return buffer.array();
    }

    public void engineSetSeed(byte[] seed) {
        System.arraycopy(seed, 0,state,0, 32);
    }

}
