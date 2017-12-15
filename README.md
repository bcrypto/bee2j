# bee2j
Java library implements Belarussian cryptographic standards  
## Linux
1. Download and compile  bee2: https://github.com/agievich/bee2  
2. Add libbee2.so to ldconfig:
	```su -c "echo '/home/PATH/TO/FOLDER/CONTAINING/BEE2/' >  /etc/ld.so.conf.d/bee2.conf"```
	sudo ldconfig  
3. Install openjdk-7 and maven2 ```sudo apt-get install openjdk-7-jdk maven2```  
4. ```mvn test```  

Windows  
1. Download and compile  bee2: https://github.com/agievich/bee2  
2. Add bee2.dll to environmental variables.  
3. Install jdk-7 and maven2   
4. ```mvn install -Dmaven.test.skip=true```  
License  
jbee2 is released under the terms of the GNU General Public License version 3 (GNU GPLv3). See LICENSE for more information.
