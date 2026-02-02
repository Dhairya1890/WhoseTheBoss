import json
from typing import Dict, List
from uuid import UUID, uuid4
from pathlib import Path

class Storage:
    def __init__(self, filepath: str = "chat_session.json"):
        self.filepath = Path(filepath)
        self.sessions: Dict[UUID, List[Dict]] = {}
        self.load_from_file()

    def load_from_file(self):
        if self.filepath.exists():
            try:
                with open(self.filepath, 'r') as f:
                    data = json.load(f)
                    self.sessions = data

            except json.JSONDecodeError:
                self.sessions = {}
        else:
            self.sessions = {}
    
    def save_to_file(self):

        serializable_data = {}

        for key, value in self.sessions.items():

            str_key = str(key) if isinstance(key, UUID) else key
            serializable_data[str_key] = value
        
        with open(self.filepath, 'w') as f:
            json.dump(serializable_data, f, indent=2, default=UUID)

    def add_session(self, session_id: UUID) -> None:
        self.sessions[str(session_id)] = []
        self.save_to_file()

    def add_message(self, session_id:UUID, message_data: Dict) -> None:
        str_id = str(session_id)
        if str_id in self.sessions:
            self.sessions[str_id].append(message_data)
            self.save_to_file()

    def get_session(self, session_id: UUID) -> List[Dict]:
        return self.sessions.get(str(session_id), [])
    
    def session_exists(self, session_id: UUID) -> bool:

        return str(session_id) in self.sessions
    
    def get_all_sessions(self) ->List[str]:
        return list(self.sessions.keys())