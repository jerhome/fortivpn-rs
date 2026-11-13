# Licences tierces

fortivpn-rs est distribué sous licence **Apache-2.0**. Ce fichier liste les composants tiers
embarqués. Il est généré à partir de `cargo metadata` (champ `license` de chaque crate) ;
les textes complets de licence sont fournis dans les sources de chaque crate.

## Slint (interface graphique `fortivpn-gui`)

- Crates : `slint`, `slint-build`, `i-slint-*` (version 1.13.1).
- Licence : **Slint Royalty-free Desktop, Mobile, and Web Applications License v2.0**
  (choisie parmi les licences proposées : GPL-3.0-only, Royalty-free, ou licence commerciale).
- Texte et conditions : <https://slint.dev/terms-and-conditions> et <https://slint.dev/royalty-free>.
- Exigence d'attribution : l'application affiche le widget `AboutSlint` (écran « À propos »,
  accessible depuis Réglages).

## Dépendances directes du workspace

| Crate | Version | Licence |
|---|---|---|
| aes | 0.8.4 | MIT OR Apache-2.0 |
| aes-gcm | 0.10.3 | Apache-2.0 OR MIT |
| bytes | 1.12.1 | MIT |
| cbc | 0.1.2 | MIT OR Apache-2.0 |
| chrono | 0.4.45 | MIT OR Apache-2.0 |
| clap | 4.6.7 | MIT OR Apache-2.0 |
| des | 0.8.1 | MIT OR Apache-2.0 |
| dirs | 6.0.0 | MIT OR Apache-2.0 |
| futures-util | 0.3.34 | MIT OR Apache-2.0 |
| hmac | 0.12.1 | MIT OR Apache-2.0 |
| httparse | 1.10.1 | MIT OR Apache-2.0 |
| i-slint-backend-testing | 1.13.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 |
| ipnet | 2.12.2 | MIT OR Apache-2.0 |
| libloading | 0.8.9 | ISC |
| md4 | 0.10.2 | MIT OR Apache-2.0 |
| nix | 0.30.1 | MIT |
| nix | 0.31.3 | MIT |
| num-bigint | 0.4.8 | MIT OR Apache-2.0 |
| p256 | 0.13.2 | Apache-2.0 OR MIT |
| proptest | 1.12.0 | MIT OR Apache-2.0 |
| quick-xml | 0.41.0 | MIT |
| quick-xml | 0.42.0 | MIT |
| rcgen | 0.14.10 | MIT OR Apache-2.0 |
| ring | 0.17.14 | Apache-2.0 AND ISC |
| rpassword | 7.5.5 | Apache-2.0 |
| rtnetlink | 0.24.0 | MIT |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT |
| rustls-native-certs | 0.8.5 | Apache-2.0 OR ISC OR MIT |
| secrecy | 0.10.3 | Apache-2.0 OR MIT |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| sha1 | 0.10.7 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| slint | 1.13.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 |
| slint-build | 1.13.1 | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 |
| smoltcp | 0.12.0 | 0BSD |
| socket2 | 0.6.5 | MIT OR Apache-2.0 |
| subtle | 2.6.1 | BSD-3-Clause |
| thiserror | 1.0.69 | MIT OR Apache-2.0 |
| thiserror | 2.0.21 | MIT OR Apache-2.0 |
| tokio | 1.54.1 | MIT |
| tokio-rustls | 0.26.6 | MIT OR Apache-2.0 |
| tokio-tun | 0.15.3 | MIT OR Apache-2.0 |
| toml | 0.8.23 | MIT OR Apache-2.0 |
| toml | 1.2.1+spec-1.1.0 | MIT OR Apache-2.0 |
| tracing | 0.1.44 | MIT |
| tracing-subscriber | 0.3.23 | MIT |
| windows-service | 0.8.1 | MIT OR Apache-2.0 |
| windows-sys | 0.48.0 | MIT OR Apache-2.0 |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 |
| windows-sys | 0.60.2 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| wintun | 0.5.1 | MIT |
| zeroize | 1.9.1 | Apache-2.0 OR MIT |

## Toutes les dépendances transitives (par licence)

### (MIT OR Apache-2.0) AND NCSA

libfuzzer-sys 0.4.13

### (MIT OR Apache-2.0) AND Unicode-3.0

unicode-ident 1.0.27, unicode-properties 0.1.5

### 0BSD

managed 0.8.0, smoltcp 0.12.0

### 0BSD OR MIT OR Apache-2.0

adler2 2.0.1

### Apache-2.0

ab_glyph 0.2.32, ab_glyph_rasterizer 0.1.10, clang-sys 1.9.1, gethostname 1.1.0, gl_generator 0.14.0, glutin 0.32.3, glutin_egl_sys 0.7.1, glutin_glx_sys 0.6.1, glutin_wgl_sys 0.6.1, khronos_api 3.1.0, linked_hash_set 0.1.6, owned_ttf_parser 0.25.1, rpassword 7.5.5, rtoolbox 0.0.6, unicode-linebreak 0.1.5, winit 0.30.13

### Apache-2.0 AND ISC

ring 0.17.14

### Apache-2.0 AND MIT

dpi 0.1.2

### Apache-2.0 OR ISC OR MIT

rustls 0.23.46, rustls-native-certs 0.8.5

### Apache-2.0 OR MIT

aes-gcm 0.10.3, async-channel 2.5.0, async-executor 1.14.1, async-io 2.6.0, async-lock 3.5.0, async-process 2.5.0, async-signal 0.2.14, async-task 4.7.1, atomic-waker 1.1.2, auto_enums 0.8.10, autocfg 1.5.1, base16ct 0.2.0, bit-vec 0.9.1, blocking 1.7.0, concurrent-queue 2.5.0, const-oid 0.9.6, crypto-bigint 0.5.5, ctor 0.10.1, der 0.7.10, derive_utils 0.16.0, dtor 0.8.1, elliptic-curve 0.13.8, equivalent 1.0.3, event-listener 5.4.2, event-listener-strategy 0.5.4, fastrand 2.5.0, futures-lite 2.6.1, ghash 0.5.1, idna_adapter 1.2.2, indexmap 2.14.2, kurbo 0.11.3, muda 0.17.2, no_std_io2 0.9.4, p256 0.13.2, parking 2.2.1, pin-project 1.1.13, pin-project-internal 1.1.13, pin-project-lite 0.2.17, polling 3.11.0, polyval 0.6.2, portable-atomic 1.15.0, primeorder 0.13.6, resvg 0.45.1, rustc-hash 2.1.3, sec1 0.7.3, secrecy 0.10.3, simd_cesu8 1.2.0, simplecss 0.2.2, spin_on 0.1.1, svgtypes 0.15.3, usvg 0.45.1, utf8_iter 1.1.0, utf_types 1.0.0, uuid 1.29.2, zeroize 1.9.1

### Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT

io-lifetimes 1.0.11, linux-raw-sys 0.12.1, linux-raw-sys 0.4.15, linux-raw-sys 0.9.4, rustix 0.38.44, rustix 1.1.6, wasi 0.11.1+wasi-snapshot-preview1, wasip2 1.0.4+wasi-0.2.12, wit-bindgen 0.57.1

### Apache-2.0/MIT

cexpr 0.6.0, integer-sqrt 0.1.5, rustc-hash 1.1.0

### BSD-2-Clause

arrayref 0.3.9, av1-grain 0.2.5, rav1e 0.8.1, v_frame 0.3.9

### BSD-2-Clause OR Apache-2.0 OR MIT

zerocopy 0.8.63, zerocopy-derive 0.8.63

### BSD-3-Clause

avif-serialize 0.8.9, bindgen 0.72.1, c2rust-bitfields 0.18.0, c2rust-bitfields-derive 0.18.0, exr 1.74.3, lebe 0.5.3, ravif 0.13.0, subtle 2.6.1, tiny-skia 0.11.4, tiny-skia-path 0.11.4

### BSD-3-Clause OR Apache-2.0

moxcms 0.8.1, pxfm 0.1.30

### BSD-3-Clause OR MIT OR Apache-2.0

num_enum 0.7.6, num_enum_derive 0.7.6

### BSL-1.0

clipboard-win 5.4.3, error-code 3.4.0

### CC0-1.0 OR Apache-2.0

imgref 1.12.3

### GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0

i-slint-backend-linuxkms 1.13.1, i-slint-backend-selector 1.13.1, i-slint-backend-testing 1.13.1, i-slint-backend-winit 1.13.1, i-slint-common 1.13.1, i-slint-compiler 1.13.1, i-slint-core 1.13.1, i-slint-core-macros 1.13.1, i-slint-renderer-skia 1.13.1, slint 1.13.1, slint-build 1.13.1, slint-macros 1.13.1

### ISC

libloading 0.8.9, rustls-webpki 0.103.17, untrusted 0.9.0

### MIT

aligned-vec 0.6.4, android-properties 0.2.2, arg_enum_proc_macro 0.3.4, av-scenechange 0.14.1, bincode 2.0.1, block2 0.5.1, block2 0.6.2, built 0.8.1, bytes 1.12.1, calloop 0.13.0, calloop 0.14.5, calloop-wayland-source 0.3.0, calloop-wayland-source 0.4.1, cfg_aliases 0.2.2, clru 0.6.3, color_quant 1.1.0, combine 4.6.9, convert_case 0.10.0, core_maths 0.1.1, crunchy 0.2.4, data-encoding 2.11.1, derive_more 2.1.1, derive_more-impl 2.1.1, dispatch 0.2.0, dlib 0.5.3, drm 0.14.1, drm-ffi 0.9.1, drm-fourcc 2.2.0, drm-sys 0.8.1, endi 1.1.1, equator 0.4.2, equator-macro 0.4.2, fax 0.2.7, float-cmp 0.9.0, fontconfig-parser 0.5.8, fontdb 0.23.0, generic-array 0.14.7, glutin-winit 0.5.0, imagesize 0.13.0, input 0.9.1, input-sys 1.19.0, interpolate_name 0.2.4, libm 0.2.16, libredox 0.1.25, libudev-sys 0.1.4, linereader 0.4.0, loop9 0.1.5, maybe-rayon 0.1.1, memoffset 0.9.1, mio 1.2.5, netlink-packet-core 0.9.0, netlink-packet-route 0.34.0, netlink-proto 0.14.1, netlink-sys 0.9.0, new_debug_unreachable 1.0.6, nix 0.30.1, nix 0.31.3, nom 7.1.3, nom 8.0.0, noop_proc_macro 0.3.0, nu-ansi-term 0.50.3, objc-sys 0.3.5, objc2 0.5.3, objc2 0.6.5, objc2-app-kit 0.2.2, objc2-cloud-kit 0.2.2, objc2-contacts 0.2.2, objc2-core-data 0.2.2, objc2-core-image 0.2.2, objc2-core-location 0.2.2, objc2-encode 4.1.0, objc2-foundation 0.2.2, objc2-foundation 0.3.2, objc2-link-presentation 0.2.2, objc2-metal 0.2.2, objc2-quartz-core 0.2.2, objc2-symbols 0.2.2, objc2-ui-kit 0.2.2, objc2-uniform-type-identifiers 0.2.2, objc2-user-notifications 0.2.2, orbclient 0.3.55, pico-args 0.5.0, pin-weak 1.1.0, polib 0.2.0, quick-xml 0.41.0, quick-xml 0.42.0, redox_syscall 0.4.1, redox_syscall 0.5.18, redox_syscall 0.9.5, redox_users 0.5.3, rgb 0.8.53, rtnetlink 0.24.0, rustybuzz 0.20.1, schannel 0.1.30, sctk-adwaita 0.10.1, sharded-slab 0.1.7, simd-adler32 0.3.10, simd_helpers 0.1.0, skia-bindings 0.87.0, skia-safe 0.87.0, slab 0.4.12, smithay-client-toolkit 0.19.2, smithay-client-toolkit 0.20.0, smithay-clipboard 0.7.3, strict-num 0.1.1, strsim 0.11.1, strum 0.27.2, strum_macros 0.27.2, synstructure 0.13.2, synstructure 0.14.0, tiff 0.11.3, tokio 1.54.1, tokio-macros 2.7.2, tracing 0.1.44, tracing-attributes 0.1.31, tracing-core 0.1.36, tracing-subscriber 0.3.23, udev 0.9.3, uds_windows 1.2.1, wayland-backend 0.3.17, wayland-client 0.31.15, wayland-csd-frame 0.3.0, wayland-cursor 0.31.14, wayland-protocols 0.32.13, wayland-protocols-experimental 20250721.0.1, wayland-protocols-misc 0.3.12, wayland-protocols-plasma 0.3.12, wayland-protocols-wlr 0.3.12, wayland-scanner 0.31.11, wayland-sys 0.31.11, winnow 0.7.15, winnow 1.0.5, wintun 0.5.1, x11-clipboard 0.9.3, x11-dl 2.21.0, xcursor 0.3.11, xkbcommon 0.8.0, xkbcommon-dl 0.4.2, xml-rs 0.8.29, xmlwriter 0.1.0, y4m 0.8.0, zbus 5.19.0, zbus_macros 5.19.0, zbus_names 4.3.5, zcheapstr 1.2.0, zmij 1.0.23, zvariant 5.15.1, zvariant_derive 5.15.1, zvariant_utils 4.2.0

### MIT / Apache-2.0

cgl 0.3.2, copypasta 0.10.2

### MIT OR Apache-2.0

aead 0.5.2, aes 0.8.4, ahash 0.8.12, aligned 0.4.3, allocator-api2 0.2.21, android-activity 0.6.1, android_system_properties 0.1.6, anstyle 1.0.14, anyhow 1.0.104, arbitrary 1.5.0, arrayvec 0.7.8, as-raw-xcb-connection 1.0.1, as-slice 0.2.1, asn1-rs 0.7.2, asn1-rs-derive 0.6.0, async-broadcast 0.7.2, async-recursion 1.2.0, async-trait 0.1.92, base64 0.22.1, bit_field 0.10.4, bitflags 2.13.2, block-buffer 0.10.4, block-padding 0.3.3, borsh 1.8.1, bumpalo 3.20.3, by_address 1.2.1, cbc 0.1.2, cc 1.11.2, cfg-if 1.0.5, chacha20 0.10.2, chrono 0.4.45, cipher 0.4.4, clap 4.6.7, clap_builder 4.6.7, clap_derive 4.6.7, clap_lex 1.1.1, const-field-offset 0.1.5, const-field-offset-macro 0.1.5, core-foundation 0.10.1, core-foundation 0.9.4, core-foundation-sys 0.8.7, core-graphics 0.23.2, core-graphics-types 0.1.3, countme 3.0.1, cpufeatures 0.2.17, cpufeatures 0.3.1, crc32fast 1.5.5, critical-section 1.2.0, crossbeam-channel 0.5.17, crossbeam-deque 0.8.8, crossbeam-epoch 0.9.21, crossbeam-utils 0.8.23, crypto-common 0.1.7, ctr 0.9.2, data-url 0.3.2, defmt 0.3.101, defmt 1.2.0, defmt-macros 1.2.0, defmt-parser 1.1.0, der-parser 10.0.0, deranged 0.5.9, des 0.8.1, digest 0.10.7, dirs 6.0.0, dirs-sys 0.5.0, displaydoc 0.2.7, either 1.19.0, enumflags2 0.7.12, enumflags2_derive 0.7.12, errno 0.3.15, euclid 0.22.14, fdeflate 0.3.7, field-offset 0.3.6, find-msvc-tools 0.1.15, flate2 1.1.11, form_urlencoded 1.2.2, futures 0.3.34, futures-channel 0.3.34, futures-core 0.3.34, futures-executor 0.3.34, futures-io 0.3.34, futures-macro 0.3.34, futures-sink 0.3.34, futures-task 0.3.34, futures-util 0.3.34, getrandom 0.2.17, getrandom 0.3.4, getrandom 0.4.3, gif 0.13.3, gif 0.14.2, glob 0.3.4, half 2.7.1, hash32 0.3.1, hashbrown 0.14.5, hashbrown 0.15.5, hashbrown 0.16.1, hashbrown 0.17.1, heapless 0.8.0, heck 0.5.0, hermit-abi 0.3.9, hermit-abi 0.5.3, hex 0.4.3, hkdf 0.12.4, hmac 0.12.1, httparse 1.10.1, iana-time-zone 0.1.65, iana-time-zone-haiku 0.1.2, idna 1.1.0, image 0.25.10, image-webp 0.2.4, inout 0.1.4, ipnet 2.12.2, itertools 0.13.0, itertools 0.14.0, itoa 1.0.19, jni 0.22.4, jni-macros 0.22.4, jni-sys 0.3.1, jni-sys 0.4.1, jni-sys-macros 0.4.1, jobserver 0.1.35, js-sys 0.3.107, keyboard-types 0.7.0, lazy_static 1.5.1, libc 0.2.191, log 0.4.35, lyon_algorithms 1.0.22, lyon_extra 1.1.0, lyon_geom 1.0.20, lyon_path 1.0.19, md4 0.10.2, memmap2 0.9.12, multiversion 0.8.1, multiversion-macros 0.8.1, ndk 0.9.0, ndk-context 0.1.1, ndk-sys 0.6.0+11769913, num-bigint 0.4.8, num-conv 0.2.2, num-derive 0.4.2, num-integer 0.1.47, num-rational 0.4.2, num-traits 0.2.19, oid-registry 0.8.1, once_cell 1.21.4, opaque-debug 0.3.1, openssl-probe 0.2.2, ordered-stream 0.2.0, paste 1.0.15, pastey 0.1.1, percent-encoding 2.3.2, pin-utils 0.1.1, piper 0.2.5, pkg-config 0.3.34, png 0.17.16, png 0.18.1, powerfmt 0.2.1, ppv-lite86 0.2.21, prettyplease 0.2.37, proc-macro-crate 3.5.0, proc-macro2 1.0.107, profiling 1.0.18, profiling-procmacros 1.0.18, proptest 1.12.0, quote 1.0.47, rand 0.10.3, rand 0.9.5, rand_chacha 0.9.0, rand_core 0.10.1, rand_core 0.6.4, rand_core 0.9.5, rand_xorshift 0.5.0, raw-window-metal 1.1.0, rayon 1.12.0, rayon-core 1.13.0, rcgen 0.14.10, regex 1.13.1, regex-automata 0.4.18, regex-syntax 0.8.11, rowan 0.16.1, roxmltree 0.20.0, rustc_version 0.4.1, rustls-pki-types 1.16.0, rustversion 1.0.23, scopeguard 1.2.0, security-framework 3.7.0, security-framework-sys 2.17.0, semver 1.0.28, serde 1.0.229, serde_core 1.0.229, serde_derive 1.0.229, serde_json 1.0.154, serde_repr 0.1.21, serde_spanned 0.6.9, serde_spanned 1.1.3, sha1 0.10.7, sha2 0.10.9, shlex 1.3.0, shlex 2.0.1, signal-hook-registry 1.4.8, simdutf8 0.1.5, siphasher 1.0.4, smallvec 1.16.5, smol_str 0.2.2, smol_str 0.3.7, socket2 0.6.5, softbuffer 0.4.8, stable_deref_trait 1.2.1, syn 1.0.109, syn 2.0.119, syn 3.0.10, sys-locale 0.3.2, tar 0.4.46, target-features 0.1.6, tempfile 3.27.0, text-size 1.1.1, thiserror 1.0.69, thiserror 2.0.21, thiserror-impl 1.0.69, thiserror-impl 2.0.21, thread_local 1.1.10, time 0.3.55, time-core 0.1.9, time-macros 0.2.32, tokio-rustls 0.26.6, tokio-tun 0.15.3, toml 0.8.23, toml 1.2.1+spec-1.1.0, toml_datetime 0.6.11, toml_datetime 0.7.5+spec-1.1.0, toml_datetime 1.1.3+spec-1.1.0, toml_edit 0.22.27, toml_edit 0.23.10+spec-1.0.0, toml_edit 0.25.19+spec-1.1.0, toml_parser 1.1.5+spec-1.1.0, toml_write 0.1.2, toml_writer 1.2.0+spec-1.1.0, ttf-parser 0.25.1, typed-index-collections 3.5.0, typenum 1.20.1, unarray 0.1.4, unicode-bidi 0.3.18, unicode-script 0.5.9, unicode-segmentation 1.13.3, unicode-xid 0.2.6, universal-hash 0.5.1, unty 0.0.4, url 2.5.8, vtable 0.3.0, vtable-macro 0.3.0, wasm-bindgen 0.2.130, wasm-bindgen-futures 0.4.80, wasm-bindgen-macro 0.2.130, wasm-bindgen-macro-support 0.2.130, wasm-bindgen-shared 0.2.130, web-sys 0.3.107, web-time 1.1.0, weezl 0.1.12, widestring 1.2.1, windows 0.58.0, windows 0.61.3, windows-collections 0.2.0, windows-core 0.58.0, windows-core 0.61.2, windows-core 0.62.2, windows-future 0.2.1, windows-implement 0.58.0, windows-implement 0.60.2, windows-interface 0.58.0, windows-interface 0.59.3, windows-link 0.1.3, windows-link 0.2.1, windows-numerics 0.2.0, windows-result 0.2.0, windows-result 0.3.4, windows-result 0.4.1, windows-service 0.8.1, windows-strings 0.1.0, windows-strings 0.4.2, windows-strings 0.5.1, windows-sys 0.48.0, windows-sys 0.52.0, windows-sys 0.60.2, windows-sys 0.61.2, windows-targets 0.48.5, windows-targets 0.52.6, windows-targets 0.53.5, windows-threading 0.1.0, windows_aarch64_gnullvm 0.48.5, windows_aarch64_gnullvm 0.52.6, windows_aarch64_gnullvm 0.53.1, windows_aarch64_msvc 0.48.5, windows_aarch64_msvc 0.52.6, windows_aarch64_msvc 0.53.1, windows_i686_gnu 0.48.5, windows_i686_gnu 0.52.6, windows_i686_gnu 0.53.1, windows_i686_gnullvm 0.52.6, windows_i686_gnullvm 0.53.1, windows_i686_msvc 0.48.5, windows_i686_msvc 0.52.6, windows_i686_msvc 0.53.1, windows_x86_64_gnu 0.48.5, windows_x86_64_gnu 0.52.6, windows_x86_64_gnu 0.53.1, windows_x86_64_gnullvm 0.48.5, windows_x86_64_gnullvm 0.52.6, windows_x86_64_gnullvm 0.53.1, windows_x86_64_msvc 0.48.5, windows_x86_64_msvc 0.52.6, windows_x86_64_msvc 0.53.1, x11rb 0.13.2, x11rb-protocol 0.13.2, x509-parser 0.18.1, xattr 1.7.0, yasna 0.6.0

### MIT OR Apache-2.0 OR LGPL-2.1-or-later

r-efi 5.3.0, r-efi 6.0.0

### MIT OR Apache-2.0 OR Zlib

cursor-icon 1.2.0, fontdue 0.9.5, glow 0.16.0, raw-window-handle 0.6.2, tiny-xlib 0.2.5, xkeysym 0.2.1, zune-core 0.4.12, zune-core 0.5.3, zune-inflate 0.2.54, zune-jpeg 0.4.21, zune-jpeg 0.5.15

### MIT OR Zlib OR Apache-2.0

miniz_oxide 0.8.9, miniz_oxide 0.9.1

### MIT/Apache-2.0

asn1-rs-impl 0.2.0, bitflags 1.3.2, bitstream-io 4.10.0, codemap 0.1.3, codemap-diagnostic 0.1.2, core_detect 1.0.0, downcast-rs 1.2.1, ff 0.13.1, filetime 0.2.29, foreign-types 0.5.0, foreign-types-macros 0.2.4, foreign-types-shared 0.3.1, group 0.13.0, linked-hash-map 0.5.6, minimal-lexical 0.2.1, plain 0.2.3, qoi 0.4.1, quick-error 2.0.1, rusticata-macros 4.1.0, scoped-tls 1.0.1, scoped-tls-hkt 0.1.5, unicode-bidi-mirroring 0.4.0, unicode-ccc 0.4.0, unicode-vo 0.1.0, version_check 0.9.5

### MPL-2.0

option-ext 0.2.0

### Unicode-3.0

icu_collections 2.4.0, icu_locale_core 2.4.0, icu_normalizer 2.4.0, icu_normalizer_data 2.4.0, icu_properties 2.4.0, icu_properties_data 2.4.0, icu_provider 2.4.0, litemap 0.8.3, potential_utf 0.1.6, tinystr 0.8.5, writeable 0.6.4, yoke 0.8.4, yoke-derive 0.8.4, zerofrom 0.1.8, zerofrom-derive 0.1.8, zerotrie 0.2.5, zerovec 0.11.9, zerovec-derive 0.11.7

### Unlicense OR MIT

aho-corasick 1.1.5, byteorder 1.5.0, byteorder-lite 0.1.0, memchr 2.8.3, termcolor 1.4.1, winapi-util 0.1.11

### Unlicense/MIT

same-file 1.0.6, walkdir 2.5.0

### Zlib

foldhash 0.1.5, foldhash 0.2.0, slotmap 1.1.1, zlib-rs 0.6.8

### Zlib OR Apache-2.0 OR MIT

bytemuck 1.25.2, bytemuck_derive 1.12.1, dispatch2 0.3.1, objc2-app-kit 0.3.2, objc2-cloud-kit 0.3.2, objc2-core-data 0.3.2, objc2-core-foundation 0.3.2, objc2-core-graphics 0.3.2, objc2-core-image 0.3.2, objc2-core-text 0.3.2, objc2-core-video 0.3.2, objc2-io-surface 0.3.2, objc2-metal 0.3.2, objc2-quartz-core 0.3.2, tinyvec 1.13.3

