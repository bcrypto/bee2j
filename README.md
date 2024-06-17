# bee2j

Java library implements Belarussian cryptographic standards  
## Linux
1. Download and compile bee2: https://github.com/agievich/bee2  
2. Add libbee2.so to ldconfig:
```
su -c "echo '/home/PATH/TO/FOLDER/CONTAINING/BEE2/' >  /etc/ld.so.conf.d/bee2.conf"
sudo ldconfig  
```
3. Install openjdk-11 and maven ```sudo apt-get install openjdk-11-jdk maven```  
4. ```mvn test``` 
5. ```mvn clean install``` 

## Windows  
1. Download and compile  bee2: https://github.com/agievich/bee2  
2. Add bee2.dll to environmental variables.  
3. Install jdk-11 (https://docs.microsoft.com/en-us/java/openjdk/download) and maven2   
4. ```mvn install -Dmaven.test.skip=true```  

## License  
bee2j is distributed under the Apache License version 2.0. See 
[Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0) or 
[LICENSE](LICENSE.txt) for details.
