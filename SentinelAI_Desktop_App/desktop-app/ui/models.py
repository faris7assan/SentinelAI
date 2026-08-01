from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex

class DataTableModel(QAbstractTableModel):
    def __init__(self, data=None, headers=None, parent=None):
        super().__init__(parent)
        self._data = data or []
        self._headers = headers or []

    def rowCount(self, parent=QModelIndex()):
        return len(self._data)

    def columnCount(self, parent=QModelIndex()):
        return len(self._headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        
        if 0 <= row < len(self._data):
            item = self._data[row]
            if role == Qt.DisplayRole:
                return str(item.get(self._headers[col].get("key", ""), ""))
            elif role == Qt.ForegroundRole:
                if col == 0 and "color" in item:
                    from PyQt5.QtGui import QColor
                    return QColor(item["color"])
            elif role == Qt.UserRole:
                return item.get("raw", {})
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            if 0 <= section < len(self._headers):
                return self._headers[section].get("title", "")
        return None

    def update_data(self, new_data):
        self.beginResetModel()
        self._data = new_data
        self.endResetModel()

    def get_raw_data(self, row):
        if 0 <= row < len(self._data):
            return self._data[row].get("raw", {})
        return None
