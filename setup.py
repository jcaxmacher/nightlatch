from setuptools import setup

def readme():
    with open('README.rst') as f:
        return f.read()

setup(name='latchbolt',
      version='0.1',
      description='A more secure way to provide access to bastion hosts on AWS',
      long_description=readme(),
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Topic :: Text Processing :: Linguistic',
      ],
      keywords='AWS',
      url='http://github.com/jcaxmacher/latchbolt',
      author='J Axmacher',
      author_email='jeremy@obsoleter.com',
      license='MIT',
      packages=['latchbolt_cli'],
      install_requires=[],
      include_package_data=True,
      zip_safe=False)