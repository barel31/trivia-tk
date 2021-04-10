##############################################################################
# server.py
##############################################################################
import socket
import chatlib
import random
import select
import ast
import requests
import json
import datetime
import html

# GLOBALS
users = {}
questions = {}
logged_users = {} # a dictionary of client hostnames to usernames
messages_to_send = []
in_question = {}

ERROR_MSG = chatlib.PROTOCOL_SERVER['error_msg']
SERVER_PORT = 1502
SERVER_IP = "localhost"
# SERVER_IP = "192.168.1.200"
# SERVER_PORT = 5678
MAX_MSG_LENGTH = 1024


# HELPER SOCKET METHODS

def build_and_send_message(conn, cmd, data: str):
    """
    Builds a new message using chatlib, wanted code and message.
    Prints debug info, then sends it to the given socket.
    Parameters: conn (socket object), code (str), data (str)
    Returns: Nothing
    """
    msg = chatlib.build_message(cmd, data)
    # if msg is not None:
    # 	conn.send(msg.encode())
    messages_to_send.append((conn, msg))


def recv_message_and_parse(conn):
    """
    Receives a new message from given socket,
    then parses the message using chatlib.
    Parameters: conn (socket object)
    Returns: cmd (str) and data (str) of the received message.
    If error occurred, will return None, None
    """
    try:
        full_msg = conn.recv(MAX_MSG_LENGTH).decode()
    except (ConnectionResetError, ConnectionAbortedError):
        full_msg = chatlib.build_message(chatlib.PROTOCOL_CLIENT['logout_msg'], '')
    if full_msg != '':
        cmd, data = chatlib.parse_message(full_msg)
        print(datetime.datetime.now(), '[CLIENT]', conn.getpeername(), full_msg)
        return cmd, data


def print_client_sockets(conn_lst):
    for conn in conn_lst:
        print(conn.getpeername())


# Data Loaders #

def load_questions_from_web():
    r = requests.get("https://opentdb.com/api.php?amount=50&difficulty=easy&type=multiple")
    # r.text.replace("&#039;", "'").replace("&quot;", "'").replace("&amp;", "&")
    j = json.loads(r.text)
    for count, question in enumerate(j['results'], 1):
        answers = question['incorrect_answers'] + [question['correct_answer']]
        random.shuffle(answers)
        fixed_replaced_question = question["question"].replace("&#039;", "'").replace("&quot;", "'").replace("&amp;", "&")
        fixed_replaced_answers = [answer.replace("&#039;", "'").replace("&quot;", "'").replace("&amp;", "&") for answer in answers]

        if fixed_replaced_question.find('#') != -1 or fixed_replaced_question.find('|' or answers.find("#") != -1 or answers.find("|" != -1)) != -1:
            print('passing question occurred when loading questions from web\nloop #', count)
        else:
            questions[count] = {
                "question": html.unescape(fixed_replaced_question),
                "answers": html.unescape(fixed_replaced_answers),
                "correct": answers.index(question['correct_answer']) + 1}


# def load_questions_from_web():
# 	# r = requests.get("https://opentdb.com/api.php?amount=50&type=multiple")
# 	r = requests.get("https://opentdb.com/api.php?amount=50&difficulty=easy&type=multiple")
# 	r.text.replace("&#039;", "'")
# 	j = json.loads(r.text)
#
# 	for count, question in enumerate(j['results']):
# 		answers = question['incorrect_answers']+[question['correct_answer']]
# 		fixed_replaced_question = question["question"].replace("&#039;", "'").replace("&quot;", "'").replace("&amp;", "&")
#
# 		if fixed_replaced_question.find('#') != -1 or fixed_replaced_question.find('|') != -1:
# 			print('passing question occurred when loading questions from web\nloop #', count)
# 			pass
#
# 		random.shuffle(answers)
#
# 		questions[count] = {
# 			"question": fixed_replaced_question,
# 			"answers": answers,
# 			"correct": answers.index(question['correct_answer'])+1}


# def load_questions():
# 	"""
# 	Loads questions bank from file	## FILE SUPPORT TO BE ADDED LATER
# 	Receives: -
# 	Returns: questions dictionary
# 	"""
# 	with open('questions.txt') as f: # read from file questions.txt
# 		for line in f:
# 			questions[int(line[:4])] = ast.literal_eval(line[6:])
#
# 	return questions


def load_user_database(write=False):
    """
    Loads users list from file
    Receives: -
    Returns: user dictionary
    """
    if not write:
        with open('users.txt') as f: # read from file users.txt
            for line in f:
                key, value = line.rstrip().split(':', 1)
                user = key.replace('\'', '')
                users[user] = ast.literal_eval(value[1:])
                users[user]['questions_asked'] = []
    else:
        with open('users.txt', 'w') as f:
            f.write(str(users)[1:-1].replace('}, ', '}\n'))

    return users


# SOCKET CREATOR

def setup_socket():
    """
    Creates new listening socket and returns it
    Receives: -
    Returns: the socket object
    """
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.bind((SERVER_IP, SERVER_PORT))
    skt.listen()
    print('The server is up and running\n', SERVER_IP, SERVER_PORT)

    return skt


def send_error(conn, error_msg):
    """
    Send error message with given message
    Receives: socket, message error string from called function
    Returns: None
    """
    build_and_send_message(conn, ERROR_MSG, error_msg)


# MESSAGE HANDLING

def create_random_question(username):
    questions_asked = users[username]['questions_asked']
    questions_not_asked = [x for x in questions.keys() if x not in questions_asked]

    if len(questions_not_asked) == 0: # No question remain
        return None
    question = random.choice(questions_not_asked)

    in_question[username] = question

    proto_question = f'{question}#{questions[question]["question"]}#{chatlib.join_data(questions[question]["answers"])}'
    return proto_question


def handle_question_message(conn, username):
    question = create_random_question(username)
    if question is None:
        build_and_send_message(conn, chatlib.PROTOCOL_SERVER['no_questions_msg'], '')
    else:
        build_and_send_message(conn, chatlib.PROTOCOL_SERVER['your_question_msg'], question)


def handle_answer_message(conn, username, data):
    question_num, answer = chatlib.split_data(data)

    if username in in_question and in_question[username] == int(question_num):
        del in_question[username]

        try:
            correct_answer = questions[int(question_num)]['correct']
        except:
            correct_answer = 0
            print('[EXCEPT] correct_answer = 0')


        if correct_answer == int(answer):
            build_and_send_message(conn, chatlib.PROTOCOL_SERVER['correct_answer_msg'], '')
            users[username]['score'] += 5
            users[username]['questions_asked'] += [int(question_num)]
            load_user_database(write=True) # TODO move to somewhere else
        else:
            build_and_send_message(conn, chatlib.PROTOCOL_SERVER['wrong_answer_msg'], str(correct_answer))
    else:
        send_error(conn, 'You are not able to get answer to this question')


def handle_logged_message(conn):
    msg = ''
    for key, value in logged_users.items():
        msg += value+','
    msg = msg[:-1]
    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['logged_msg'], msg)


def handle_getscore_message(conn, username):
    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['your_score_msg'], str(users[username]['score']))


def handle_highscore_message(conn):
    highscore = sorted(users.items(), key=lambda item: item[1]['score'], reverse=True)
    highscore_msg, count = '', 0
    for score in highscore:
        count += 1
        highscore_msg += f'{score[0]}\t{score[1]["score"]}\n'
        if count == 10: # top ten
            break

    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['all_score_msg'], highscore_msg)


def handle_logout_message(conn):
    """
    Closes the given socket (in laster chapters, also remove user from logged_users dictionary)
    Receives: socket
    Returns: None
    """
    if conn in logged_users:
        del logged_users[conn]
    conn.close()


def handle_login_message(conn, data):
    """
    Gets socket and message data of login message. Checks  user and pass exists and match.
    If not - sends error and finished. If all ok, sends OK message and adds user and address to logged_users
    Receives: socket, message code and data
    Returns: None (sends answer to client)
    """
    fail_message = False

    try:
        user, password = chatlib.split_data(data)
    except ValueError:
        send_error(conn, 'Data field incorrect')
    else:
        for key in users:
            if key == user:
                fail_message = True
                if password == users[user]['password']:
                    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['login_ok_msg'], '')
                    logged_users[conn] = user
                    break
                else:
                    build_and_send_message(conn, chatlib.PROTOCOL_SERVER['login_failed_msg'], 'Password does not match!')

        if not fail_message:
            build_and_send_message(conn, chatlib.PROTOCOL_SERVER['login_failed_msg'], 'Username does not exist')


def handle_client_message(conn, cmd, data):
    """
    Gets message code and data and calls the right function to handle command
    Receives: socket, message code and data
    Returns: None
    """
    if conn not in logged_users: # client not logged in yet, allow login only
        if cmd == chatlib.PROTOCOL_CLIENT['login_msg']:
            handle_login_message(conn, data)
        else:
            send_error(conn, 'You have to login first')
    else: # client is logged in already, handle message
        if cmd == '' or cmd == chatlib.PROTOCOL_CLIENT['logout_msg']:
            handle_logout_message(conn)
        elif cmd == chatlib.PROTOCOL_CLIENT['my_score_msg']:
            handle_getscore_message(conn, logged_users[conn])
        elif cmd == chatlib.PROTOCOL_CLIENT['high_score_msg']:
            handle_highscore_message(conn)
        elif cmd == chatlib.PROTOCOL_CLIENT['logged_msg']:
            handle_logged_message(conn)
        elif cmd == chatlib.PROTOCOL_CLIENT['get_question_msg']:
            handle_question_message(conn, logged_users[conn])
        elif cmd == chatlib.PROTOCOL_CLIENT['send_answer_msg']:
            handle_answer_message(conn, logged_users[conn], data)
        else:
            send_error(conn, 'Command is invalid')


def main():
    global users
    global questions

    users = load_user_database()
    # questions = load_questions()
    load_questions_from_web()

    print("Welcome to Trivia Server!")
    server_socket = setup_socket()

    # Multiplayer loop made by select
    client_sockets = []
    while True:
        ready_to_read, ready_to_write, in_error = select.select([server_socket] + client_sockets, client_sockets, [])
        for current_socket in ready_to_read:
            if current_socket is server_socket:
                (client_socket, client_address) = server_socket.accept()
                print('New client joined!', client_address)
                client_sockets.append(client_socket)
            else:
                try:
                    cmd, data = recv_message_and_parse(current_socket)
                except (ConnectionResetError, ConnectionAbortedError, TypeError): # Handle client disconnect without logout msg
                    cmd, data = chatlib.PROTOCOL_CLIENT['logout_msg'], ''

                if cmd == chatlib.PROTOCOL_CLIENT['logout_msg']:
                    handle_logout_message(current_socket)
                    client_sockets.remove(current_socket)
                    print_client_sockets(client_sockets)
                else:
                    handle_client_message(current_socket, cmd, data)

        # queue for sending messages to clients
        for current_socket, data in messages_to_send:
            if current_socket in ready_to_write:
                try:
                    current_socket.send(data.encode())
                except:
                    print('[EXCEPT]', 'cannot send data:', data)
                print(datetime.datetime.now(), '[SERVER]', current_socket.getpeername(), data)
                messages_to_send.remove((current_socket, data))


if __name__ == '__main__':
    main()
