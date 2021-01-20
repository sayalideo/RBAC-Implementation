# RBAC-Implementation
An NSS Council Management System which implements the RBAC (Role Based Access Control) Model.

Step I : Installing Python : 
  sudo apt update
  sudo apt -y upgrade
  sudo apt install -y python3-pip

Step II : Installing Flask :
  On Linux, virtualenv is provided by your package manager:
  //Debian, Ubuntu
  $ sudo apt-get install python-virtualenv
  //CentOS, Fedora
  $ sudo yum install python-virtualenv
  //Arch
  $ sudo pacman -S python-virtualenv

  mkdir myproject
  cd myproject
  python3 -m venv venv
  . venv/bin/activate
  $ pip install Flask

Step III : Installing SQL-Alchemy : 
  $ pip install sqlalchemy

Step IV : Clone the repository from github using the command -
  $ git clone https://github.com/sayalideo/RBAC-Implementation

Step V : Installing other Dependencies : 
  $ pip install bcrypt
  $ pip install flask-login
  $ pip install flask-wtf

Step VI : Run the code using : 
  $ python run.py
  Or
  $ flask run

Now, view the running application on localhost:5000

