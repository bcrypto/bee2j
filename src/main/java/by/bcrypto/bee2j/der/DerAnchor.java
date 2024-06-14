package by.bcrypto.bee2j.der;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/*!	\brief Якорь для кодирования контейнеров */
@Structure.FieldOrder({"der", "pos", "tag", "len"})
public class DerAnchor extends Structure implements Structure.ByReference {
	public Pointer der;	    /*!< код */
	public long pos;			/*!< позиция */
	public int tag;			/*!< тег */
	public long len;			/*!< длина */
}