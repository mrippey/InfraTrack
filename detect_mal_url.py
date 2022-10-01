"""_detect_mal_url.py_ - Detect malicious domains using Logistic Regression"""

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from rich.console import Console
from core.logs import LOG

LOG.info("Starting detect_mal_url.py")
console = Console()

domain_dataset = pd.read_csv(
        "/Users/m_a_t/Documents/Python_Projects/infratrackr/url_data1.csv"
    )

def detect_domains(word_list):
    """_summary_ - Detect malicious domains using Logistic Regression"""

    LOG.debug("Loading test dataset")

    data = domain_dataset["url"]
    classifier = domain_dataset["label"]
    LOG.debug("Splitting dataset into training and testing sets")
    vectorizer = TfidfVectorizer()
    x_info = vectorizer.fit_transform(data)
    x_train, x_test, y_train, y_test = train_test_split(
        x_info, classifier, test_size=0.2, random_state=42
    )
    LOG.debug("Training model")
    model = LogisticRegression(max_iter=1000)
    model.fit(x_train, y_train)
    LOG.debug("Testing model")
    score = model.score(x_test, y_test)
    console.print(f"[*] Model accuracy: {score:.2f}", style="bold white")
    LOG.debug("Model accuracy: %s", score)
    print()

    LOG.debug("Predicting malicious domains")
    with open(
        word_list,
        "r",
    ) as outfile:
        word_list = outfile.readlines()
    domain_matches = [line.strip() for line in word_list]

    predictions = model.predict(vectorizer.transform(domain_matches))

    mal_domains_file = '/Users/m_a_t/Documents/Python_Projects/infratrackr/mal_domains.txt'
    console.print(f'[*] Results written to: {mal_domains_file}', style='bold green')
    for i in range(len(domain_matches)):  #range(len(text))
        
        if predictions[i] == "bad":

            with open(mal_domains_file, "a") as output_file:
                output_file.write(domain_matches[i] + "\n")
                LOG.info("[+] Writing results to file...")
    LOG.info("Finished detect_mal_url.py")
  

  

