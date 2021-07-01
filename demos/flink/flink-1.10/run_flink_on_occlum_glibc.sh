#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'
occlum_glibc=/opt/occlum/glibc/lib/

init_flink_instance() {
    # Init Occlum Flink instance
    postfix=$1
    FLINK_LOG_PREFIX="/host/flink--$postfix-${id}"
    log="${FLINK_LOG_PREFIX}.log"
    out="./flink--$postfix-${id}.out"

    rm -rf occlum_instance_$postfix && mkdir occlum_instance_$postfix
    cd occlum_instance_$postfix
    occlum init
    new_json="$(jq '.resource_limits.user_space_size = "5500MB" |
        .resource_limits.kernel_space_heap_size="64MB" |
        .resource_limits.max_num_of_threads = 64 |
        .process.default_heap_size = "128MB" |
        .process.default_mmap_size = "5000MB" |
        .entry_points = [ "/usr/lib/jvm/java-11-openjdk-amd64/bin" ] |
        .env.default = [ "LD_LIBRARY_PATH=/usr/lib/jvm/java-11-openjdk-amd64/lib/server:/usr/lib/jvm/java-11-openjdk-amd64/lib:/usr/lib/jvm/java-11-openjdk-amd64/../lib:/lib" ]' Occlum.json)" && \
    echo "${new_json}" > Occlum.json
}

init_flink_and_fish_instance() {
    # Init Occlum Flink & Fish instance
    postfix=$1
    FLINK_LOG_PREFIX="/host/flink--$postfix-${id}"
    log="${FLINK_LOG_PREFIX}.log"
    out="./flink--$postfix-${id}.out"

    rm -rf occlum_instance_$postfix && mkdir occlum_instance_$postfix
    cd occlum_instance_$postfix
    occlum init
    new_json="$(jq '.resource_limits.user_space_size = "11000MB" |
        .resource_limits.kernel_space_heap_size="64MB" |
        .resource_limits.max_num_of_threads = 64 |
        .process.default_heap_size = "128MB" |
        .process.default_mmap_size = "5000MB" |
        .entry_points = [ "/bin/bin" ] |
        .env.default = [ "LD_LIBRARY_PATH=/usr/lib/jvm/java-11-openjdk-amd64/lib/server:/usr/lib/jvm/java-11-openjdk-amd64/lib:/usr/lib/jvm/java-11-openjdk-amd64/../lib:/lib", "HOME=/root", "FLINK_CONF_DIR=/bin/conf" ]' Occlum.json)" && \
    echo "${new_json}" > Occlum.json
}

build_flink() {
    # Copy JVM and class file into Occlum instance and build
    mkdir -p image/usr/lib/jvm
    cp -r /usr/lib/jvm/java-11-openjdk-amd64 image/usr/lib/jvm
    cp /lib/x86_64-linux-gnu/libz.so.1 image/lib
    cp $occlum_glibc/libdl.so.2 image/$occlum_glibc
    cp $occlum_glibc/librt.so.1 image/$occlum_glibc
    cp $occlum_glibc/libm.so.6 image/$occlum_glibc
    cp $occlum_glibc/libnss_files.so.2 image/$occlum_glibc
    cp -rf ../flink-1.10.1/* image/bin/
    cp -rf ../hosts image/etc/
    occlum build
}

build_flink_and_fish() {
    # Copy JVM and class file into Occlum instance
    mkdir -p image/usr/lib/jvm
    cp -r /usr/lib/jvm/java-11-openjdk-amd64 image/usr/lib/jvm
    cp /lib/x86_64-linux-gnu/libz.so.1 image/lib
    cp $occlum_glibc/libdl.so.2 image/$occlum_glibc
    cp $occlum_glibc/librt.so.1 image/$occlum_glibc
    cp $occlum_glibc/libm.so.6 image/$occlum_glibc
    cp $occlum_glibc/libnss_files.so.2 image/$occlum_glibc
    cp -rf ../flink-1.10.1/* image/bin/
    cp -rf ../hosts image/etc/
    # Copy Fish and busybox file into Occlum instance
    mkdir -p image/usr/bin
    cp ../fish-shell/build/fish image/usr/bin
    cp ../busybox/busybox image/usr/bin
    pushd image/bin
    ln -s /usr/bin/busybox cat
    ln -s /usr/bin/busybox echo
    ln -s /usr/bin/busybox awk
    popd
    # Build Occlum instance
    occlum build
}

run_jobmanager() {
    # Run Flink JobManager
    init_flink_instance jobmanager
    build_flink
    echo -e "${BLUE}occlum run Flink JobManager${NC}"
    echo -e "${BLUE}logfile=$log${NC}"
    occlum run /usr/lib/jvm/java-11-openjdk-amd64/bin/java \
        -Xmx800m -XX:-UseCompressedOops -XX:MaxMetaspaceSize=256m -XX:ActiveProcessorCount=2 \
        -Dos.name=Linux \
        -Dlog.file=$log \
        -Dlog4j.configuration=file:/bin/conf/log4j.properties \
        -Dlog4j.configurationFile=file:/bin/conf/log4j.properties \
        -Dlogback.configurationFile=file:/bin/conf/logback.xml \
        -classpath /bin/lib/flink-table-blink_2.11-1.10.1.jar:/bin/lib/flink-table_2.11-1.10.1.jar:/bin/lib/log4j-1.2.17.jar:/bin/lib/slf4j-log4j12-1.7.15.jar:/bin/lib/flink-dist_2.11-1.10.1.jar org.apache.flink.runtime.entrypoint.StandaloneSessionClusterEntrypoint \
        --configDir /bin/conf \
        --executionMode cluster \
    &
}

run_taskmanager() {
  # Run Flink TaskManager
    init_flink_instance taskmanager
    build_flink
    echo -e "${BLUE}occlum run Flink TaskManager${NC}"
    echo -e "${BLUE}logfile=$log${NC}"
    occlum run /usr/lib/jvm/java-11-openjdk-amd64/bin/java \
        -Xmx800m -XX:-UseCompressedOops -XX:MaxMetaspaceSize=256m -XX:ActiveProcessorCount=2 \
        -Dos.name=Linux \
        -Dlog.file=$log \
        -Dlog4j.configuration=file:/bin/conf/log4j.properties \
        -Dlog4j.configurationFile=file:/bin/conf/log4j.properties \
        -Dlogback.configurationFile=file:/bin/conf/logback.xml \
        -classpath /bin/lib/flink-table-blink_2.11-1.10.1.jar:/bin/lib/flink-table_2.11-1.10.1.jar:/bin/lib/log4j-1.2.17.jar:/bin/lib/slf4j-log4j12-1.7.15.jar:/bin/lib/flink-dist_2.11-1.10.1.jar org.apache.flink.runtime.taskexecutor.TaskManagerRunner \
        --configDir /bin/conf \
        -D taskmanager.memory.network.max=64mb \
        -D taskmanager.memory.network.min=64mb \
        -D taskmanager.memory.managed.size=128mb \
        -D taskmanager.cpu.cores=1.0 \
        -D taskmanager.memory.task.heap.size=256mb \
    &
}

run_task() {
    # Run Flink task
    init_flink_and_fish_instance task
    build_flink_and_fish
    echo -e "${BLUE}occlum run Flink task${NC}"
    echo -e "${BLUE}logfile=$log${NC}"
    occlum run /bin/bin/flink run /bin/examples/streaming/WordCount.jar
}

id=$([ -f "$pid" ] && echo $(wc -l < "$pid") || echo "0")

arg=$1
case "$arg" in
	jm)
        run_jobmanager
	    cd ../
        ;;
    tm)
        run_taskmanager
	    cd ../
        ;;
    task)
        run_task
        cd ../
        ;;
esac
