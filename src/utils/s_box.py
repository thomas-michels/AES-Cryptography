
class SBox:

    table = {
        "0": {"0": "63", "1": "7C", "2": "77", "3": "7B", "4": "F2", "5": "6B", "6": "6F", "7": "C5", "8": "30", "9": "01", "A": "67", "B": "2B", "C": "FE", "D": "D7", "E": "AB", "F": "76"},
        "1": {"0": "CA", "1": "82", "2": "C9", "3": "7D", "4": "FA", "5": "59", "6": "47", "7": "F0", "8": "AD", "9": "D4", "A": "A2", "B": "AF", "C": "9C", "D": "A4", "E": "72", "F": "C0"},
        "2": {"0": "B7", "1": "FD", "2": "93", "3": "26", "4": "36", "5": "3F", "6": "F7", "7": "CC", "8": "34", "9": "A5", "A": "E5", "B": "F1", "C": "71", "D": "D8", "E": "31", "F": "15"},
        "3": {"0": "04", "1": "C7", "2": "23", "3": "C3", "4": "18", "5": "96", "6": "05", "7": "9A", "8": "07", "9": "12", "A": "80", "B": "E2", "C": "EB", "D": "27", "E": "B2", "F": "75"},
        "4": {"0": "09", "1": "83", "2": "2C", "3": "1A", "4": "1B", "5": "6E", "6": "5A", "7": "A0", "8": "52", "9": "3B", "A": "D6", "B": "B3", "C": "29", "D": "E3", "E": "2F", "F": "84"},
        "5": {"0": "53", "1": "D1", "2": "00", "3": "ED", "4": "20", "5": "FC", "6": "B1", "7": "5B", "8": "6A", "9": "CB", "A": "BE", "B": "39", "C": "4A", "D": "4C", "E": "58", "F": "CF"},
        "6": {"0": "D0", "1": "EF", "2": "AA", "3": "FB", "4": "43", "5": "4D", "6": "33", "7": "85", "8": "45", "9": "F9", "A": "02", "B": "7F", "C": "50", "D": "3C", "E": "9F", "F": "A8"},
        "7": {"0": "51", "1": "A3", "2": "40", "3": "8F", "4": "92", "5": "9D", "6": "38", "7": "F5", "8": "BC", "9": "B6", "A": "DA", "B": "21", "C": "10", "D": "FF", "E": "F3", "F": "D2"},
        "8": {"0": "CD", "1": "0C", "2": "13", "3": "EC", "4": "5F", "5": "97", "6": "44", "7": "17", "8": "C4", "9": "A7", "A": "7E", "B": "3D", "C": "64", "D": "5D", "E": "19", "F": "73"},
        "9": {"0": "60", "1": "81", "2": "4F", "3": "DC", "4": "22", "5": "2A", "6": "90", "7": "88", "8": "46", "9": "EE", "A": "B8", "B": "14", "C": "DE", "D": "5E", "E": "0B", "F": "DB"},
        "A": {"0": "E0", "1": "32", "2": "3A", "3": "0A", "4": "49", "5": "06", "6": "24", "7": "5C", "8": "C2", "9": "D3", "A": "AC", "B": "62", "C": "91", "D": "95", "E": "E4", "F": "79"},
        "B": {"0": "E7", "1": "C8", "2": "37", "3": "6D", "4": "8D", "5": "D5", "6": "4E", "7": "A9", "8": "6C", "9": "56", "A": "F4", "B": "EA", "C": "65", "D": "7A", "E": "AE", "F": "08"},
        "C": {"0": "BA", "1": "78", "2": "25", "3": "2E", "4": "1C", "5": "A6", "6": "B4", "7": "C6", "8": "E8", "9": "DD", "A": "74", "B": "1F", "C": "4B", "D": "BD", "E": "8B", "F": "8A"},
        "D": {"0": "70", "1": "3E", "2": "B5", "3": "66", "4": "48", "5": "03", "6": "F6", "7": "0E", "8": "61", "9": "35", "A": "57", "B": "B9", "C": "86", "D": "C1", "E": "1D", "F": "9E"},
        "E": {"0": "E1", "1": "F8", "2": "98", "3": "11", "4": "69", "5": "D9", "6": "8E", "7": "94", "8": "9B", "9": "1E", "A": "87", "B": "E9", "C": "CE", "D": "55", "E": "28", "F": "DF"},
        "F": {"0": "8C", "1": "A1", "2": "89", "3": "0D", "4": "BF", "5": "E6", "6": "42", "7": "68", "8": "41", "9": "99", "A": "2D", "B": "0F", "C": "B0", "D": "54", "E": "BB", "F": "16"},
    }

    def get_hex(self, line: str, column: str) -> str:
        return self.table[line.upper()][column.upper()]
