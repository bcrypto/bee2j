# bee2j
[![wercker status](https://app.wercker.com/status/915547776b9b5f56c2b9bb989f3187c2/m/ "wercker status")](https://app.wercker.com/project/byKey/915547776b9b5f56c2b9bb989f3187c2)

Java library implements Belarussian cryptographic standards  
## Linux
1. Download and compile  bee2: https://github.com/agievich/bee2  
2. Add libbee2.so to ldconfig:
	```su -c "echo '/home/PATH/TO/FOLDER/CONTAINING/BEE2/' >  /etc/ld.so.conf.d/bee2.conf"```
	sudo ldconfig  
3. Install openjdk-16 and maven2 ```sudo apt-get install openjdk-16-jdk maven2```  
4. ```mvn test```  

## Windows  
1. Download and compile  bee2: https://github.com/agievich/bee2  
2. Add bee2.dll to environmental variables.  
3. Install jdk-16 (https://docs.microsoft.com/en-us/java/openjdk/download) and maven2   
4. ```mvn install -Dmaven.test.skip=true```  

##License  
bee2j is released under the terms of the GNU General Public License version 3 (GNU GPLv3). See LICENSE for more information.
