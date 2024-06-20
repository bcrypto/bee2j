package by.bcrypto.bee2j.der;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

@Structure.FieldOrder({"der", "pos", "tag", "len"})
public class DerAnchor extends Structure implements Structure.ByReference {
	public Pointer der;
	public long pos;
	public int tag;
	public long len;
}