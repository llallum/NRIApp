
from setuptools import setup, find_packages
from glob import glob

with open('requirements.txt') as f:
    requirements = f.read().splitlines()


setup(
   name='nriapp',
   version='1.0.10',
   description='This is an internal tool for crawling MS 365 Defender web with NRI',
   author='Llallum Victoria',
   author_email='llallumvictoria@gmail.com',
#   packages=find_packages('chrome'),
   package_dir = {'':'src'},
    
   packages=['.', 'config', 'core', 'helper'],  #same as name
#   packages=find_packages(exclude=['ez_setup', 'tests', 'tests.*']),
   data_files=[('', ['./src/requirements.txt', './src/changelog.txt']),
               ('./session', glob('./src/session/*.*')),
               ('./logs', glob('./src/logs/*.*')),
               ('./output', glob('./src/output/*.*'))

               ],
   #setup_requires=['session', 'logs', 'output'],
   include_package_data=True,  
   install_requires=requirements, #external packages as dependencies,
   entry_points = '''
        [console_scripts]
        nriapp=nriapp:main
    '''

)
