package by.bcrypto.bee2j;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/*!	\brief Якорь для кодирования контейнеров */
@Structure.FieldOrder({"der", "pos", "tag", "len"})
public class DerAnchor extends Structure implements Structure.ByReference {
	public Pointer der;	    /*!< код */
	public int pos;			/*!< позиция */
	public int tag;			/*!< тег */
	public int len;			/*!< длина */
}