import sys
import os
import ctypes
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit,
    QProgressBar, QFileDialog, QHBoxLayout, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler



if sys.platform.startswith("win"):
    # 현재 스크립트 파일이 있는 폴더의 절대 경로를 구합니다.
    dll_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. 시스템 환경 변수 PATH의 맨 앞에 이 폴더를 강제로 추가합니다.
    os.environ["PATH"] = dll_dir + os.pathsep + os.environ["PATH"]
    
    # Python 3.8 이상을 위한 추가 안전장치
    try:
        os.add_dll_directory(dll_dir)
    except AttributeError:
        pass


# C++ 엔진 불러오기
if sys.platform.startswith("win"):
    libname = "antivirus_core.dll"
else:
    libname = "libantivirus_core.so"

try:
    engine = ctypes.CDLL(os.path.join(os.path.dirname(__file__), libname))

    # 함수 시그니처 설정: c_char_p 대신 c_wchar_p를 사용하여 유니코드 경로를 전달합니다.
    engine.scan_file.argtypes = [ctypes.c_wchar_p] 
    engine.scan_file.restype = ctypes.c_int

except FileNotFoundError as e:
    print(f"\n[치명적 오류] DLL 파일을 찾을 수 없습니다: {libname}")
    print(f"현재 탐색 경로: {os.path.dirname(os.path.abspath(__file__))}")
    print(f"상세 에러: {e}\n")
    sys.exit(1)
except OSError as e:
    print(f"\n[치명적 오류] DLL 로드 실패 (아키텍처 불일치 가능성): {e}\n")
    sys.exit(1)

def scan_file(filepath):
    # C++ DLL이 wchar_t* (유니코드)를 기대하므로, 인코딩 없이 Python 문자열을 그대로 전달
    result = engine.scan_file(filepath) 
    
    if result == 1:
        return f"[악성] {filepath}"
    elif result == 2:
        return f"[악성해시] {filepath}"
    elif result == 0:
        return f"[정상] {filepath}"
    else:
        # C++ 엔진의 반환 값(-1)을 확인하기 위한 디버그 출력
        print(f"DEBUG: C++ scan_file returned error code: {result} (File Access Failure)") 
        return f"[오류] {filepath}"

# 다중 검사용 스레드
class BatchScanThread(QThread):
    progress = pyqtSignal(int)
    result_msg = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, file_list):
        super().__init__()
        self.file_list = file_list

    def run(self):
        n = len(self.file_list)
        for i, f in enumerate(self.file_list, 1):
            res = scan_file(f)
            self.result_msg.emit(res)
            self.progress.emit(i)
        self.finished.emit()

# 실시간 폴더 모니터링용 이벤트 핸들러
class FolderHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
    def on_created(self, event):
        # 새 파일 등장할 때만 검사(단일 파일만)
        if not event.is_directory:
            res = scan_file(event.src_path)
            self.callback(res)

class AntivirusGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("백신 데모")
        self.setGeometry(400, 200, 700, 500)
        layout = QVBoxLayout()

        btn_layout = QHBoxLayout()
        self.select_btn = QPushButton('파일 여러 개 선택/검사')
        self.select_btn.clicked.connect(self.choose_and_scan)
        self.folder_btn = QPushButton('폴더 내 파일 전체 검사')
        self.folder_btn.clicked.connect(self.scan_folder)
        self.monitor_btn = QPushButton('폴더 실시간 감시 시작')
        self.monitor_btn.setCheckable(True)
        self.monitor_btn.toggled.connect(self.toggle_monitoring)
        btn_layout.addWidget(self.select_btn)
        btn_layout.addWidget(self.folder_btn)
        btn_layout.addWidget(self.monitor_btn)
        layout.addLayout(btn_layout)

        layout.addWidget(QLabel("검사 결과 로그:"))
        self.result_box = QTextEdit(readOnly=True)
        layout.addWidget(self.result_box)
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        self.setLayout(layout)

        self.observer = None
        self.monitor_thread = None

    # 다중 파일 선택 검사
    def choose_and_scan(self):
        files, _ = QFileDialog.getOpenFileNames(self, "여러 파일 선택")
        self._start_batch_scan(files)

    # 선택한 폴더 내 모든 파일 검사
    def scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "검사할 폴더 선택")
        if folder:
            file_list = []
            for root, _, files in os.walk(folder):
                for name in files:
                    file_list.append(os.path.join(root, name))
            self._start_batch_scan(file_list)

    def _start_batch_scan(self, files):
        if not files:
            return
        self.progress.setMaximum(len(files))
        self.progress.setValue(0)
        self.result_box.append("[*] 검사 시작...\n")
        self.scan_thread = BatchScanThread(files)
        self.scan_thread.progress.connect(self.progress.setValue)
        self.scan_thread.result_msg.connect(self.result_box.append)
        self.scan_thread.finished.connect(lambda: QMessageBox.information(self, "완료", "전체 검사 완료!"))
        self.scan_thread.start()

    # 폴더 실시간 감시 on/off
    def toggle_monitoring(self, checked):
        if checked:
            dir_ = QFileDialog.getExistingDirectory(self, "실시간 감시할 폴더 선택")
            if not dir_:
                self.monitor_btn.setChecked(False)
                return
            self.monitor_btn.setText("폴더 실시간 감시 중지")
            self.result_box.append(f"[실시간 감시 시작] {dir_}")
            self.observer = Observer()
            handler = FolderHandler(self.result_box.append)
            self.observer.schedule(handler, dir_, recursive=False)
            self.observer.start()
        else:
            try:
                self.observer.stop()
                self.observer.join()
                self.result_box.append("[실시간 감시 중지]")
            except Exception:
                pass
            self.monitor_btn.setText("폴더 실시간 감시 시작")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = AntivirusGUI()
    win.show()
    sys.exit(app.exec_())