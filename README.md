CA Trust Management System (CA-TMS)  
Contact: jbraun@cdc.informatik.tu-darmstadt.de

CA-TMS Team:  
Johannes Braun  
Pascal Weisenburger

Former team members:  
Haixin Cai  
Jannik Vieten


Building the CA-TMS
===================

1. clone the git repository

        $ git clone https://github.com/ca-tms/CA-TMS.git

2. build the CA-TMS Java application (using the included Eclipse project or the
   Ant build file)
 
        $ cd CA-TMS/trustviewapplication
        $ ant jar

    All library dependencies of the Java application are included in the
    repository and are packaged into the built JAR file. The library used to
    query notary services can be found in the
    [ca-tms/sslcheck](https://github.com/ca-tms/sslcheck) repository.

3. build the Firefox extension by packing the
   `trustviewextension@cdc.informatik.tu-darmstadt.de` directory into a ZIP file

        $ cd ../trustviewextension@cdc.informatik.tu-darmstadt.de
        $ zip -r CA-TMS.xpi content defaults locale skin chrome.manifest install.rdf


Installing and running the CA-TMS
=================================

Install the Firefox extension by dragging the `CA-TMS.xpi` into the Firefox
browser and run the CA-TMS Java application `CA-TMS.jar`. The application must
be running in the background while using the Firefox extension.
