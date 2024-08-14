from reverzeX import ReverzeX

if __name__ == '__main__':
    try:
        reverzeX = ReverzeX()
        reverzeX.start()
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        logging.critical(f"An unexpected error occurred: {str(e)}")
