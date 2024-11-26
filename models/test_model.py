import pickle

print("Загрузка модели.......")
with open("model.pkl", "rb") as rf:
    clf = pickle.load(rf)

print("Загрузка векторизатора.......")
with open("vector.pkl", "rb") as rf:
    vectorizer = pickle.load(rf)

print("Предсказания....")
test_data = ["Чтобы использовать ваш кредит, нажмите на wap-ссылку в следующем текстовом сообщении или перейдите по этой ссылке",
             "Привет, надеюсь, у тебя всё хорошо"]
test_data_features = vectorizer.transform(test_data)
print(test_data)
print(clf.predict(test_data_features))
