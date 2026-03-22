"""
Scan QR WiFi to Auto-Connect (Windows)

Dependensi:
- opencv-python
- pyzbar

Format QR WiFi yang didukung (standar):
WIFI:S:<SSID>;T:<TYPE>;P:<PASS>;;
"""

import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional

import cv2
from pyzbar.pyzbar import decode


# Mapping tipe keamanan QR ke nilai authentication untuk profil WLAN XML Windows.
AUTH_MAP = {
	"WPA": "WPA2PSK",
	"WPA2": "WPA2PSK",
	"WPA3": "WPA3SAE",
	"WEP": "open",
	"NOPASS": "open",
	"": "open",
}

# Opsi scan: mode cepat untuk kamera burik, dan preview non-mirror.
FAST_SCAN_MODE = True
FORCE_UNMIRROR_PREVIEW = True


def apply_camera_capture_mode(camera: cv2.VideoCapture, fast_mode: bool) -> None:
	# Terapkan preset capture untuk mode cepat atau stabil saat runtime.
	if fast_mode:
		camera.set(cv2.CAP_PROP_BUFFERSIZE, 1)
		camera.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
		camera.set(cv2.CAP_PROP_FPS, 30)
		camera.set(cv2.CAP_PROP_FRAME_WIDTH, 960)
		camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 540)
		camera.set(cv2.CAP_PROP_AUTOFOCUS, 1)
	else:
		camera.set(cv2.CAP_PROP_BUFFERSIZE, 2)
		camera.set(cv2.CAP_PROP_FPS, 24)
		camera.set(cv2.CAP_PROP_AUTOFOCUS, 1)


def run_command(command: list[str]) -> subprocess.CompletedProcess:
	# Menjalankan command shell Windows dan mengembalikan hasil lengkap stdout/stderr.
	return subprocess.run(command, capture_output=True, text=True, shell=False)


def parse_wifi_qr(payload: str) -> Optional[Dict[str, str]]:
	# Validasi format dasar QR WiFi.
	if not payload.startswith("WIFI:"):
		return None

	# Ambil isi setelah prefix WIFI: lalu pastikan separator akhir ada.
	body = payload[5:]
	if not body.endswith(";;"):
		return None

	# Hapus terminator akhir agar lebih mudah diparse.
	body = body[:-2]

	# Pecah field berdasarkan ';' yang tidak di-escape.
	parts = re.split(r"(?<!\\);", body)
	data: Dict[str, str] = {}
	for part in parts:
		if not part or ":" not in part:
			continue
		key, value = part.split(":", 1)
		# Unescape karakter standar pada format QR WiFi.
		value = (
			value.replace(r"\\;", ";")
			.replace(r"\\,", ",")
			.replace(r"\\:", ":")
			.replace(r"\\\\", r"\\")
		)
		data[key] = value

	ssid = data.get("S", "").strip()
	auth_type = data.get("T", "").strip().upper()
	password = data.get("P", "")

	# SSID wajib ada agar bisa connect.
	if not ssid:
		return None

	return {
		"ssid": ssid,
		"type": auth_type,
		"password": password,
	}


def xml_escape(value: str) -> str:
	# Escape karakter XML agar aman saat menyusun profil WLAN.
	return (
		value.replace("&", "&amp;")
		.replace("<", "&lt;")
		.replace(">", "&gt;")
		.replace('"', "&quot;")
		.replace("'", "&apos;")
	)


def build_wifi_profile_xml(ssid: str, qr_type: str, password: str) -> str:
	# Konversi tipe keamanan dari QR ke tipe autentikasi yang dikenal oleh Windows.
	auth = AUTH_MAP.get(qr_type, "WPA2PSK")

	# Profil untuk jaringan open (tanpa password).
	if auth == "open":
		return f"""<?xml version=\"1.0\"?>
<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">
	<name>{xml_escape(ssid)}</name>
	<SSIDConfig>
		<SSID>
			<name>{xml_escape(ssid)}</name>
		</SSID>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
		<security>
			<authEncryption>
				<authentication>open</authentication>
				<encryption>none</encryption>
				<useOneX>false</useOneX>
			</authEncryption>
		</security>
	</MSM>
</WLANProfile>
"""

	# Profil untuk jaringan berpassword (WPA/WPA2/WPA3/WEP).
	encryption = "AES" if auth in {"WPA2PSK", "WPA3SAE"} else "TKIP"
	if qr_type == "WEP":
		encryption = "WEP"

	return f"""<?xml version=\"1.0\"?>
<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">
	<name>{xml_escape(ssid)}</name>
	<SSIDConfig>
		<SSID>
			<name>{xml_escape(ssid)}</name>
		</SSID>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
		<security>
			<authEncryption>
				<authentication>{auth}</authentication>
				<encryption>{encryption}</encryption>
				<useOneX>false</useOneX>
			</authEncryption>
			<sharedKey>
				<keyType>passPhrase</keyType>
				<protected>false</protected>
				<keyMaterial>{xml_escape(password)}</keyMaterial>
			</sharedKey>
		</security>
	</MSM>
</WLANProfile>
"""


def create_temp_profile_file(xml_content: str, ssid: str) -> Path:
	# Simpan profil WLAN ke file XML sementara untuk dipakai perintah netsh.
	safe_ssid = re.sub(r"[^a-zA-Z0-9_-]", "_", ssid)[:30] or "wifi_profile"
	temp_path = Path(tempfile.gettempdir()) / f"{safe_ssid}_{int(time.time())}.xml"
	temp_path.write_text(xml_content, encoding="utf-8")
	return temp_path


def is_connected_to_ssid(target_ssid: str) -> bool:
	# Cek apakah perangkat sudah benar-benar tersambung ke SSID target.
	check = run_command(["netsh", "wlan", "show", "interfaces"])
	if check.returncode != 0:
		return False

	output = check.stdout.lower()
	return "state" in output and "connected" in output and target_ssid.lower() in output


def connect_wifi_using_netsh(ssid: str, qr_type: str, password: str) -> bool:
	# Membuat profil, menambahkannya ke Windows, lalu mencoba konek otomatis.
	xml_path: Optional[Path] = None
	try:
		profile_xml = build_wifi_profile_xml(ssid, qr_type, password)
		xml_path = create_temp_profile_file(profile_xml, ssid)
		print(f"[INFO] File profil dibuat: {xml_path}")

		# Tambahkan profil WiFi ke sistem.
		add_profile = run_command(
			["netsh", "wlan", "add", "profile", f"filename={str(xml_path)}"]
		)
		print("[LOG] Output add profile:")
		print(add_profile.stdout.strip() or "(tanpa output)")
		if add_profile.returncode != 0:
			print("[ERROR] Gagal menambahkan profil WiFi ke Windows.")
			if add_profile.stderr.strip():
				print(f"[ERROR] Detail: {add_profile.stderr.strip()}")
			print("[HINT] Coba jalankan terminal sebagai Administrator.")
			return False

		# Jalankan perintah connect menggunakan nama profil/SSID.
		print(f"[INFO] Mencoba konek ke SSID: {ssid}")
		connect = run_command(["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"])
		print("[LOG] Output connect:")
		print(connect.stdout.strip() or "(tanpa output)")
		if connect.returncode != 0:
			print("[ERROR] Perintah connect gagal dijalankan.")
			if connect.stderr.strip():
				print(f"[ERROR] Detail: {connect.stderr.strip()}")
			return False

		# Tunggu singkat agar proses koneksi selesai, lalu verifikasi status.
		for _ in range(6):
			time.sleep(1)
			if is_connected_to_ssid(ssid):
				print(f"[SUCCESS] Berhasil terkoneksi ke '{ssid}'.")
				return True

		print(f"[FAILED] Gagal verifikasi koneksi ke '{ssid}'.")
		return False
	finally:
		# Hapus file XML sementara apapun hasil koneksinya.
		if xml_path and xml_path.exists():
			try:
				xml_path.unlink()
				print(f"[CLEANUP] File profil sementara dihapus: {xml_path}")
			except OSError as exc:
				print(f"[WARN] Gagal menghapus file sementara: {exc}")


def scan_qr_from_camera() -> Optional[str]:
	# Di Windows, backend kamera tertentu bisa gagal grab frame; coba beberapa backend.
	fast_scan_enabled = FAST_SCAN_MODE
	backend_candidates = []
	if sys.platform.startswith("win"):
		backend_candidates = [cv2.CAP_DSHOW, cv2.CAP_MSMF, cv2.CAP_ANY]
	else:
		backend_candidates = [cv2.CAP_ANY]

	cap: Optional[cv2.VideoCapture] = None
	active_backend_name = "UNKNOWN"
	for backend in backend_candidates:
		candidate = cv2.VideoCapture(0, backend)
		if not candidate.isOpened():
			candidate.release()
			continue

		apply_camera_capture_mode(candidate, fast_scan_enabled)

		# Beberapa kamera butuh warm-up sebentar sebelum frame pertama valid.
		for _ in range(5):
			candidate.read()
			time.sleep(0.03)

		ok, _ = candidate.read()
		if ok:
			cap = candidate
			if backend == cv2.CAP_DSHOW:
				active_backend_name = "DirectShow"
			elif backend == cv2.CAP_MSMF:
				active_backend_name = "MSMF"
			else:
				active_backend_name = "AUTO"
			break

		candidate.release()

	if cap is None:
		print("[ERROR] Kamera tidak terdeteksi atau tidak bisa diakses.")
		print("[HINT] Tutup aplikasi lain yang memakai kamera (Zoom/Meet/Camera), lalu coba lagi.")
		return None

	mode_label = "FAST" if fast_scan_enabled else "STABLE"
	mirror_label = "OFF" if FORCE_UNMIRROR_PREVIEW else "ON"
	print(
		f"[INFO] Kamera aktif (backend: {active_backend_name}, mode: {mode_label}, mirror: {mirror_label})."
	)
	print("[INFO] Arahkan QR WiFi ke kamera.")
	print("[INFO] Tekan tombol 'f' untuk toggle FAST/STABLE, atau 'q' untuk keluar.")

	detected_text: Optional[str] = None
	consecutive_read_failures = 0
	max_consecutive_failures = 40
	last_fail_log_at = 0.0
	tracked_qr_rect: Optional[tuple[int, int, int, int]] = None
	tracked_seen_at = 0.0
	smoothed_guide_rect: Optional[list[float]] = None
	frame_index = 0
	last_detected_payload = ""
	last_detected_log_at = 0.0
	try:
		while True:
			frame_index += 1
			# FAST dibuat agresif, STABLE dibuat lebih hemat agar beda performa terasa.
			full_frame_interval = 1 if fast_scan_enabled else 6
			guide_color = (255, 200, 0) if fast_scan_enabled else (80, 220, 120)
			# Ambil frame kamera secara real-time.
			ok, frame = cap.read()
			if not ok:
				consecutive_read_failures += 1
				now = time.time()
				# Throttle log agar terminal tidak banjir warning saat kamera macet.
				if now - last_fail_log_at >= 1.0:
					print(
						f"[WARN] Gagal membaca frame kamera ({consecutive_read_failures}/{max_consecutive_failures})."
					)
					last_fail_log_at = now

				if consecutive_read_failures >= max_consecutive_failures:
					print("[ERROR] Kamera terus gagal mengirim frame. Scan dihentikan.")
					print("[HINT] Coba ganti kamera default atau restart aplikasi kamera lain.")
					break

				# Tetap proses keyboard event agar tombol q responsif saat frame gagal.
				if cv2.waitKey(1) & 0xFF == ord("q"):
					break
				time.sleep(0.05)
				continue

			if FORCE_UNMIRROR_PREVIEW:
				# Beberapa webcam menampilkan preview mirror; flip sekali untuk orientasi natural.
				frame = cv2.flip(frame, 1)

			consecutive_read_failures = 0
			now = time.time()
			frame_h, frame_w = frame.shape[:2]
			gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

			# Decode prioritas area QR terakhir agar tracking lebih cepat dan stabil.
			detected_items: list[tuple[int, int, int, int, str]] = []
			seen_items: set[tuple[int, int, int, int, str]] = set()

			def add_detected_item(dx: int, dy: int, dw: int, dh: int, payload: str) -> None:
				quantized_key = (
					dx // 8,
					dy // 8,
					dw // 8,
					dh // 8,
					payload,
				)
				if quantized_key in seen_items:
					return
				seen_items.add(quantized_key)
				detected_items.append((dx, dy, dw, dh, payload))

			if tracked_qr_rect and now - tracked_seen_at < 1.2:
				tx, ty, tw, th = tracked_qr_rect
				pad_x = max(35, int(tw * 0.6))
				pad_y = max(35, int(th * 0.6))
				rx1 = max(0, tx - pad_x)
				ry1 = max(0, ty - pad_y)
				rx2 = min(frame_w, tx + tw + pad_x)
				ry2 = min(frame_h, ty + th + pad_y)

				if rx2 > rx1 and ry2 > ry1:
					roi = gray_frame[ry1:ry2, rx1:rx2]
					for qr in decode(roi):
						rx, ry, rw, rh = qr.rect
						payload = qr.data.decode("utf-8", errors="ignore").strip()
						add_detected_item(rx1 + rx, ry1 + ry, rw, rh, payload)

			# Fallback decode full frame berkala agar tetap bisa lock QR baru.
			if not detected_items or frame_index % full_frame_interval == 0:
				for qr in decode(gray_frame):
					rx, ry, rw, rh = qr.rect
					payload = qr.data.decode("utf-8", errors="ignore").strip()
					add_detected_item(rx, ry, rw, rh, payload)

			# Tambahan untuk kamera burik: perjelas kontras dan upscale bila belum terbaca.
			if fast_scan_enabled and not detected_items:
				enhanced = cv2.convertScaleAbs(gray_frame, alpha=1.65, beta=16)
				scaled = cv2.resize(
					enhanced,
					None,
					fx=1.7,
					fy=1.7,
					interpolation=cv2.INTER_CUBIC,
				)
				for qr in decode(scaled):
					sx, sy, sw, sh = qr.rect
					payload = qr.data.decode("utf-8", errors="ignore").strip()
					add_detected_item(
						int(sx / 1.45),
						int(sy / 1.45),
						int(sw / 1.45),
						int(sh / 1.45),
						payload,
					)

			tracked_wifi_this_frame = False
			for x, y, w, h, payload in detected_items:
				# Gambar indikator area QR agar terlihat bagian yang sedang terbaca.
				is_wifi_qr = payload.startswith("WIFI:")
				box_color = (255, 200, 0) if is_wifi_qr else (180, 180, 180)
				box_thickness = 3 if is_wifi_qr else 2
				cv2.rectangle(frame, (x, y), (x + w, y + h), box_color, box_thickness)

				if is_wifi_qr:
					tracked_qr_rect = (x, y, w, h)
					tracked_seen_at = now
					tracked_wifi_this_frame = True

				if payload and (
					payload != last_detected_payload or now - last_detected_log_at >= 1.5
				):
					print(f"[DETECTED] QR ditemukan: {payload}")
					last_detected_payload = payload
					last_detected_log_at = now

				# Cek hanya QR format WiFi yang diproses.
				if is_wifi_qr:
					detected_text = payload
					break

			if not tracked_wifi_this_frame and tracked_qr_rect and now - tracked_seen_at >= 1.2:
				tracked_qr_rect = None

			# Guide area scan: auto pindah mengikuti QR yang sedang terbaca.
			if tracked_qr_rect:
				gx, gy, gw, gh = tracked_qr_rect
				pad = max(25, int(max(gw, gh) * 0.35))
				desired_x = max(0, gx - pad)
				desired_y = max(0, gy - pad)
				desired_w = min(frame_w - desired_x, gw + (2 * pad))
				desired_h = min(frame_h - desired_y, gh + (2 * pad))
			else:
				desired_w = int(frame_w * 0.42)
				desired_h = int(frame_h * 0.42)
				desired_x = (frame_w - desired_w) // 2
				desired_y = (frame_h - desired_h) // 2

			desired = [float(desired_x), float(desired_y), float(desired_w), float(desired_h)]
			if smoothed_guide_rect is None:
				smoothed_guide_rect = desired
			else:
				alpha = 0.38
				for i in range(4):
					smoothed_guide_rect[i] = smoothed_guide_rect[i] + alpha * (
						desired[i] - smoothed_guide_rect[i]
					)

			x1 = int(smoothed_guide_rect[0])
			y1 = int(smoothed_guide_rect[1])
			box_w = int(smoothed_guide_rect[2])
			box_h = int(smoothed_guide_rect[3])
			x2 = x1 + box_w
			y2 = y1 + box_h
			corner = max(22, min(box_w, box_h) // 7)
			mode_corner = 16

			# Marker mode tanpa teks: FAST kuning, STABLE hijau.
			cv2.line(frame, (12, 12), (12 + mode_corner, 12), guide_color, 4)
			cv2.line(frame, (12, 12), (12, 12 + mode_corner), guide_color, 4)
			cv2.line(frame, (frame_w - 12, 12), (frame_w - 12 - mode_corner, 12), guide_color, 4)
			cv2.line(frame, (frame_w - 12, 12), (frame_w - 12, 12 + mode_corner), guide_color, 4)

			# Corner indicator mengikuti posisi QR agar framing lebih cepat.
			cv2.line(frame, (x1, y1), (x1 + corner, y1), guide_color, 3)
			cv2.line(frame, (x1, y1), (x1, y1 + corner), guide_color, 3)
			cv2.line(frame, (x2, y1), (x2 - corner, y1), guide_color, 3)
			cv2.line(frame, (x2, y1), (x2, y1 + corner), guide_color, 3)
			cv2.line(frame, (x1, y2), (x1 + corner, y2), guide_color, 3)
			cv2.line(frame, (x1, y2), (x1, y2 - corner), guide_color, 3)
			cv2.line(frame, (x2, y2), (x2 - corner, y2), guide_color, 3)
			cv2.line(frame, (x2, y2), (x2, y2 - corner), guide_color, 3)

			# Tampilkan preview kamera agar user tahu proses scan sedang jalan.
			cv2.imshow("Scan QR WiFi - tekan q untuk keluar", frame)

			# Hentikan scan kalau QR valid sudah didapat.
			if detected_text:
				break

			# Hotkey runtime: f untuk toggle mode, q untuk keluar.
			key = cv2.waitKey(1) & 0xFF
			if key == ord("f"):
				fast_scan_enabled = not fast_scan_enabled
				apply_camera_capture_mode(cap, fast_scan_enabled)
				new_mode = "FAST" if fast_scan_enabled else "STABLE"
				print(f"[INFO] Mode scan diganti ke: {new_mode}")
			elif key == ord("q"):
				break
	finally:
		# Pastikan resource kamera dan jendela ditutup bersih.
		cap.release()
		cv2.destroyAllWindows()

	return detected_text


def main() -> None:
	# Alur utama: scan QR -> parse data WiFi -> connect otomatis via netsh.
	qr_payload = scan_qr_from_camera()
	if not qr_payload:
		print("[INFO] Tidak ada QR WiFi yang diproses. Program selesai.")
		return

	wifi_data = parse_wifi_qr(qr_payload)
	if not wifi_data:
		print("[ERROR] Format QR tidak valid untuk konfigurasi WiFi.")
		print("[INFO] Contoh format valid: WIFI:S:NamaSSID;T:WPA;P:password123;;")
		return

	ssid = wifi_data["ssid"]
	qr_type = wifi_data["type"]
	password = wifi_data["password"]

	print("[INFO] Data WiFi berhasil diparse:")
	print(f"       SSID : {ssid}")
	print(f"       TYPE : {qr_type or 'NOPASS'}")
	print(f"       PASS : {'*' * len(password) if password else '(kosong)'}")

	success = connect_wifi_using_netsh(ssid=ssid, qr_type=qr_type, password=password)
	if success:
		print("[FINAL] Status koneksi: BERHASIL")
	else:
		print("[FINAL] Status koneksi: GAGAL")


if __name__ == "__main__":
	main()
