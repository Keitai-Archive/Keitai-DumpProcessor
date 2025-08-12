# Keitai-DumpProcessor
Extracts and Process Keitai Dumps in whole

Categories:
- appli        = .jar, .jam, .sp, .scr, .jad, .rms
- emoji        = .gif that is exactly 20x20 px
- kisekae      = .ucp, .ucm, .vui
- charaden     = .afd
- machichara   = .cfd, .mmd
- flash        = .swf
- book files   = .zbf
- jpgs         = .jpg, .jpeg, .img  ('.img' is extracted: header 0x80, name at 0x30..0x30+35 SJIS)
- camera photos= .jpg, .jpeg, .png, .bmp where width>640 or height>480
- png          = .png  (non "camera photos")
- bmp          = .bmp  (non "camera photos")
- midi         = .mid
- melodies     = .mld, .mel
- toruca       = .trc
- videos       = .3gp, .mp2

Usage:
  python Keitai_DumpProcessor.py /path/to/input /path/to/output
  Normally use this: python Keitai_DumpProcessor.py --flatten /in /out