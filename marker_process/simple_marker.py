from marker_process.markers_process import handle_markers, send_marker_packet


handle_markers("BALISE", lambda: send_marker_packet("donnee"))
