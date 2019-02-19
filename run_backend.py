from backend import app, data_model


if __name__ == '__main__':
    data_model.create_tables()
    app.run(host='127.0.0.1', port=5000, debug=True)