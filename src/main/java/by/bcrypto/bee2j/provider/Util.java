package by.bcrypto.bee2j.provider;

import java.util.ArrayList;

public class Util {

    static public byte[] bytes(ArrayList<Byte> data) {
        byte[] bytes = new byte[data.size()];
        for (int i = 0; i < data.size(); i++)
            bytes[i] = data.get(i);

        return bytes;
    }

}
