__eh_frame_hdr_start = SIZEOF(.eh_frame_hdr) > 0 ? ADDR(.eh_frame_hdr) : 0;
__eh_frame_hdr_end = SIZEOF(.eh_frame_hdr) > 0 ? (ADDR(.eh_frame_hdr) + SIZEOF(.eh_frame_hdr)) : 0;
__eh_frame_start = SIZEOF(.eh_frame) > 0 ? ADDR(.eh_frame) : 0;
__eh_frame_end = SIZEOF(.eh_frame) > 0 ? (ADDR(.eh_frame) + SIZEOF(.eh_frame)) : 0;
