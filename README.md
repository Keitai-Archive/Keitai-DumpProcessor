# Keitai-DumpProcessor
Extracts and Process Keitai Dumps in whole
Recursive sorter for Keitai assets with:
- .img header extraction: legacy JPEG payloads at 0x80 and NEC payloads at
  0xBC, detected by JPEG magic. NEC titles start at 0x1F; legacy titles at 0x30.
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
- jpgs         = .jpg, .jpeg and supported .img JPEGs without camera evidence
- camera photos= images (including extracted .img JPEGs) with an EXIF camera
  Model, or width>640 or height>480.
- png          = .png
- bmp          = .bmp
- midi         = .mid
- melodies     = .mld, .mel, .dwn
- toruca       = .trc
- videos       = .3gp, .mp2
- PDF		  = .pdf

Usage:
  python Keitai_DumpProcessor.py /path/to/input /path/to/output
  python Keitai_DumpProcessor.py --p "SH-10C" --flatten /in /out