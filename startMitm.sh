#!/bin/bash


mvn dependency:copy-dependencies
mvn compile

currentDir=`readlink -m  $(dirname $0)`

classpath=$currentDir/target/dependency/*:$currentDir/target/classes
jvmOptions="-server -XX:PermSize=24M -XX:MaxPermSize=64m -Xms128m -Xmx448m -XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFraction=70 -XX:NewRatio=3"


printf "Starting service.....\n" 
nohup java -Djava.net.preferIPv4Stack=true  $jvmOptions -cp $classpath   org.littleshoot.proxy.Launcher --port 1443 --ssl --ssl_keystore_file ./littleProxy_xiaoman.cn.jks  --proxy_authenticator org.littleshoot.proxy.impl.BasicProxyAuthenticator 2>&1 >> $currentDir/littleProxy.log  & 
printf "Done... Ok"

tail -f littleProxy.log
