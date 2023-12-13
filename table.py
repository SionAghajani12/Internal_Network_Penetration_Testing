from prettytable import PrettyTable


def create_table(header, data):
    table = PrettyTable()
    table.field_names = header
    for row in data:
        table.add_row(row)
    return str(table)