# Keitai-DumpProcessor
Extracts and Process Keitai Dumps in whole
Recursive sorter for Keitai assets with:
- .img header extraction (name at 0x30..+35 SJIS; JPEG starts at 0x80)
- .mht / .dmt extraction:
  * Standard MHTML (multipart/related)
  * Fallback for HTTP-capture style files (concatenated HTTP/1.x responses)

Categories:
- appli        = .jar, .jam, .sp, .scr, .jad, .rms
- emoji        = .gif exactly 20x20 px
- gifs         = .gif (non-emoji)
- kisekae      = .ucp, .ucm, .vui
- charaden     = .afd
- machichara   = .cfd, .mmd
- flash        = .swf
- book files   = .zbf
- html         = .html, .htm
- jpgs         = .jpg, .jpeg, .img
- camera photos= .jpg, .jpeg, .png, .bmp where width>640 or height>480
- png          = .png
- bmp          = .bmp
- midi         = .mid
- melodies     = .mld, .mel
- toruca       = .trc
- videos       = .3gp, .mp2
- PDF		  = .pdf

Usage:
  python Keitai_DumpProcessor.py /path/to/input /path/to/output
  python Keitai_DumpProcessor.py --p "SH-10C" --flatten /in /out