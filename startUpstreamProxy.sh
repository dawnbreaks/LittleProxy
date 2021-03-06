#!/bin/bash


mvn dependency:copy-dependencies
mvn compile

currentDir=`readlink -m  $(dirname $0)`

classpath=$currentDir/target/dependency/*:$currentDir/target/classes
jvmOptions="-server -XX:PermSize=24M -XX:MaxPermSize=64m -Xms128m -Xmx448m -XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFraction=70 -XX:NewRatio=3"


printf "Starting service.....\n" 
nohup java -Djava.net.preferIPv4Stack=true  $jvmOptions -cp $classpath   org.littleshoot.proxy.Launcher --port 2443 --file ./upstreamLittleproxy.properties --ssl 2>&1 >> $currentDir/upstream.log  & 
printf "Done... Ok"

tail -f upstream.log 
