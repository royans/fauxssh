# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi

# User specific aliases and functions
alias ll='ls -l --color=auto'
alias l.='ls -d .* --color=auto'
alias ls='ls --color=auto'
export PATH=$PATH:/usr/local/cuda-8.0/bin
