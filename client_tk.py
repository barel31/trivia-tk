import socket
import chatlib  # To use chatlib functions or consts, use chatlib.****
# import getpass
from tkinter import *


SERVER_IP = "127.0.0.1"  # Our server will run on same computer as client
SERVER_PORT = 1502
# SERVER_IP = "77.124.93.4"
# SERVER_PORT = 5678
MAX_MSG_LENGTH = 1024


def build_and_send_message(conn, cmd, data):
    """
    Builds a new message using chatlib, wanted code and message.
    Prints debug info, then sends it to the given socket.
    Parameters: conn (socket object), code (str), data (str)
    Returns: Nothing
    """

    code = chatlib.build_message(cmd, data)
    if code is not None:
        conn.send(code.encode())


def recv_message_and_parse(conn):
    """
    Receives a new message from given socket,
    then parses the message using chatlib.
    Parameters: conn (socket object)
    Returns: cmd (str) and data (str) of the received message.
    If error occurred, will return None, None
    """

    full_msg = conn.recv(MAX_MSG_LENGTH).decode()

    cmd, data = chatlib.parse_message(full_msg)
    return cmd, data


def connect():
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.connect((SERVER_IP, SERVER_PORT))
    return skt


def build_send_recv_parse(conn, cmd, data):
    build_and_send_message(conn, cmd, data)
    cmd, data = recv_message_and_parse(conn)
    return cmd, data


class Window(Tk):

    def __init__(self, *args, **kwargs):

        # Socket ...
        self.conn = connect()

        # TK ...
        Tk.__init__(self, *args, **kwargs)

        self.title('Trivia!')

        self.label_top = Label(text="Welcome to my Trivia Game!")
        self.label_lower = Label()
        self.label_top.grid(row=0)

        self.label_username = Label(text="Username")
        self.label_password = Label(text="Password")
        self.entry_username = Entry()
        self.entry_password = Entry(show="*")
        self.button_login = Button(text="login", command=self.login_button)
        self.bind('<Return>', self.login_button)

        self.label_username.grid(row=1)
        self.label_password.grid(row=2)
        self.entry_username.grid(row=1, column=1)
        self.entry_password.grid(row=2, column=1)
        self.button_login.grid(columnspan=2)
        self.label_info = Label()

        self.b_question = Button(text='Get question', command=self.button_question)
        self.b_score = Button(text='My score', command=self.button_score)
        self.b_highscore = Button(text='Highscore', command=self.button_highscore)
        self.b_logged = Button(text='Logged players', command=self.button_logged)
        self.b_logout = Button(text='Logout', command=self.button_logout)

        self.button_menu = Button(text='Menu', command=self.main_menu)

        self.label_question, self.button_answer_1,  self.button_answer_2, self.button_answer_3, self.button_answer_4, \
            self.button_next = Label(self), Button(self), Button(self), Button(self), Button(self), Button(self)

    def login_button(self, event=None):
        """Handle login button"""

        build_and_send_message(self.conn, chatlib.PROTOCOL_CLIENT["login_msg"], f'{self.entry_username.get()}#{self.entry_password.get()}')
        recv = recv_message_and_parse(self.conn)

        if recv[0] == chatlib.PROTOCOL_SERVER["login_ok_msg"]:
            self.main_menu()

        else: # Failed to login
            self.label_lower.configure(text=recv[1])
            self.label_lower.grid(sticky=NE)

    def main_menu(self, action=None):
        self.wipe()

        self.b_question.grid(column=0, row=1)
        self.b_score.grid(column=0, row=2)
        self.b_highscore.grid(column=0, row=3)
        self.b_logged.grid(column=0, row=4)
        self.b_logout.grid(column=0, row=5)

        self.bind('<Return>', self.button_question)
        self.bind('<Escape>', self.button_logout)

    def button_question(self, event=None):
        """Handle question button"""
        self.wipe()
        self.b_question.grid_forget()
        self.b_score.grid_forget()
        self.b_highscore.grid_forget()
        self.b_logged.grid_forget()
        self.b_logout.grid_forget()

        cmd, data = build_send_recv_parse(self.conn, chatlib.PROTOCOL_CLIENT["get_question_msg"], '')
        fields = data.split('#')

        if cmd == chatlib.PROTOCOL_SERVER["no_questions_msg"]:
            self.label_lower.configure(text="No more questions have been left\nGAME OVER")
            self.label_lower.grid(sticky=NE)
            self.button_menu.grid()
        else:
            self.label_question = Label(text=fields[1])
            self.button_answer_1 = Button(text='1. '+fields[2], command=lambda: self.answer(fields, 1))
            self.button_answer_2 = Button(text='2. '+fields[3], command=lambda: self.answer(fields, 2))
            self.button_answer_3 = Button(text='3. '+fields[4], command=lambda: self.answer(fields, 3))
            self.button_answer_4 = Button(text='4. '+fields[5], command=lambda: self.answer(fields, 4))
            self.button_next = Button(text='Skip', command=self.handle_next)
            # TODO add sounds
            self.label_question.grid()
            self.button_answer_1.grid()
            self.button_answer_2.grid()
            self.button_answer_3.grid()
            self.button_answer_4.grid()
            self.button_next.grid()

            self.bind('1', lambda x: self.answer(fields, 1))
            self.bind('2', lambda x: self.answer(fields, 2))
            self.bind('3', lambda x: self.answer(fields, 3))
            self.bind('4', lambda x: self.answer(fields, 4))
            self.bind('<Return>', self.handle_next)

    def answer(self, fields, answer, event=None):
        """Handle answers buttons"""
        self.button_answer_1['state'], self.button_answer_2['state'], self.button_answer_3['state'], \
            self.button_answer_4['state'] = 'disabled', 'disabled', 'disabled', 'disabled'

        cmd, data = build_send_recv_parse(self.conn, chatlib.PROTOCOL_CLIENT["send_answer_msg"], f'{fields[0]}#{answer}')

        if cmd == chatlib.PROTOCOL_SERVER["correct_answer_msg"]:
            self.label_lower.configure(text="Correct! you got 5 points!")

        elif cmd == chatlib.PROTOCOL_SERVER["wrong_answer_msg"]:
            self.label_lower.configure(text=f'you dead wrong!, correct answer is ({data}) {fields[int(data) + 1]}')

        self.label_lower.grid()

        self.button_next.configure(text='Next')
        self.button_menu.grid(row=8)
        self.bind('<Escape>', self.main_menu)

    def handle_next(self, event=None):
        """Clean window and go to next question"""
        self.wipe()
        self.button_question()

    def wipe(self):
        self.button_login.grid_forget()
        self.button_next.grid_forget()
        self.button_menu.grid_forget()
        self.label_question.grid_forget()
        self.button_answer_1.grid_forget()
        self.button_answer_2.grid_forget()
        self.button_answer_3.grid_forget()
        self.button_answer_4.grid_forget()
        self.label_lower.grid_forget()
        self.label_info.grid_forget()
        self.entry_password.grid_forget()
        self.entry_username.grid_forget()
        self.label_username.grid_forget()
        self.label_password.grid_forget()

        self.unbind('1')
        self.unbind('2')
        self.unbind('3')
        self.unbind('4')

    def button_score(self):
        cmd, data = build_send_recv_parse(self.conn, chatlib.PROTOCOL_CLIENT["my_score_msg"], '')
        self.label_info.configure(text=f'Your score is {data}')
        self.label_info.grid()


    def button_highscore(self):
        cmd, data = build_send_recv_parse(self.conn, chatlib.PROTOCOL_CLIENT["high_score_msg"], '')
        self.label_info.configure(text=f'Highscore table:\n{data}')
        self.label_info.grid()


    def button_logged(self):
        cmd, data = build_send_recv_parse(self.conn, chatlib.PROTOCOL_CLIENT["logged_msg"], '')
        self.label_info.configure(text=f'Logged players:\n{data}')
        self.label_info.grid()

    def button_logout(self, action=None):
        build_and_send_message(self.conn, chatlib.PROTOCOL_CLIENT["logout_msg"], '')
        self.conn.close()

        self.label_info.configure(text=f'You have been logged out')
        self.label_info.grid()
        Tk.destroy(self)
        self.__init__()


if __name__ == '__main__':
    root = Window()
    root.minsize(width=300, height=100)
    root.mainloop()
