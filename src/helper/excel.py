import xlsxwriter


class WorkBook:
    def __init__(self, file_name):
        workbook = xlsxwriter.Workbook('Example3.xlsx')
        worksheet = workbook.add_worksheet("My sheet")

    def add_item(self, dictionary):
        pass


