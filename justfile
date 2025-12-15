# print just recipes
default:
    just -l

# build and run galmon-osnma with Galmon live feed
galmon-osnma-live-feed *args:
    nc 86.82.68.237 10000 | \
        cargo run --release --bin galmon-osnma -- {{args}}

# build and run galmon-osnma with ubxtool
galmon-osnma-ubxtool ubxtool-port *args:
    ubxtool --wait --port {{ubxtool-port}} --station 1 --stdout --galileo | \
        cargo run --release --bin galmon-osnma -- {{args}}

# build and run osnma-longan-nano client with Galmon live feed
osnma-longan-nano-live-feed longan-nano-serial:
    nc 86.82.68.237 10000 | \
        cargo run --release --bin osnma-longan-nano-client -- {{longan-nano-serial}}

# build and run osnma-longan-nano client with ubxtool
osnma-longan-nano-ubxtool ubxtool-port longan-nano-serial:
    ubxtool --wait --port {{ubxtool-port}} --station 1 --stdout --galileo | \
        cargo run --release --bin osnma-longan-nano-client -- {{longan-nano-serial}}

# process test vectors
test-vectors:
    wget --quiet https://www.gsc-europa.eu/sites/default/files/sites/all/files/Test_vectors.zip
    unzip Test_vectors.zip
    rm -rf Test_vectors.zip
    ./utils/run_test_vectors.sh Test_vectors
    rm -rf Test_vectors readme.txt

# build osnma-longan-nano firmware
osnma-longan-nano:
    cargo objcopy -p osnma-longan-nano \
        --target riscv32imac-unknown-none-elf --profile embedded \
        -- -O binary osnma-longan-nano-firmware.bin

# run clippy for osnma-longan-nano firmware
clippy-osnma-longan-nano:
    cargo clippy --all-features -p osnma-longan-nano --target riscv32imac-unknown-none-elf -- -D warnings

# flash osnma-longan-nano firmware
osnma-longan-nano-flash: osnma-longan-nano
    dfu-util -a 0 -s 0x08000000:leave -D osnma-longan-nano-firmware.bin
