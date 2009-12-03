#!/usr/bin/env python
"""
Copyright (c) 2008-2009, Anthony FOIGNANT. All rights reserved.

A simple tool which make the configuration's backup of your SAN switches simple and easy. It actually works with Cisco, Brocade and McData switches and allows you to get the configuration of your switch by SCP or FTP. You don't need to install or configure a SSH or a FTP server on your computer.

Contact Info:
  http://code.google.com/p/save-simply-your-san/
  antispameu-san@yahoo.fr
"""
#Import
try:
    import SaveSimplyyourSAN
except ImportError:
    raise ImportError, 'This program requires the SaveSimplyyourSAN extension for Python. See http://code.google.com/p/save-simply-your-san/'

try:
    import pygtk
    pygtk.require("2.0")
except ImportError:
    raise ImportError, 'This program requires the pyGTK extension for Python. See http://www.pygtk.org/'

try:
    import gtk
    import gtk.glade
except ImportError:
    raise ImportError, 'This program requires the GTK and Glade extension for Python. See http://www.pygtk.org/'

import os
import socket


# Definition of messages
RSA_msg = "A 1024 bits RSA key has been generated successfuly in the file new_server_rsa.key. The public key is stored in the file new_server_rsa.pub"
# Definition of the GUI
class GUI_App:
    """
	Class of the Graphical User Interface
	"""
    def __init__(self):
        #initialisation
        self.terminal_output = False
        #get the glade file for the interface
        self.gladefile = os.path.normcase(os.getcwd() + "/interface.glade")
        self.widgets = gtk.glade.XML(self.gladefile)
        #getting the list of the interfaces of the local computer
        ipaddrlist = socket.gethostbyname_ex(socket.gethostname())[2]
        #adding each interface to the combobox of the GUI
        for ip in ipaddrlist:
            self.widgets.get_widget('combobox-save-if').append_text(ip)
        #activate the first interface in the list
        self.widgets.get_widget('combobox-save-if').set_active(0)

        #connections to the events of the GUI
        events = { 'main_quit': self.close_app,
                   'on_button-save-start_released': self.btn_save_start_released,
                   'on_radio-mcdata_toggled': self.radio_mcdata_toggled,
                   'on_radio-cisco_toggled': self.radio_cisco_toggled,
                   'on_radio-brocade_toggled': self.radio_brocade_toggled,
                   'on_button-option-generate_clicked': self.btn_option_generate_clicked,
                   'on_button-exec-start_released': self.btn_exec_start_released,
                   'on_check-term_toggled': self.check_term_toggled
                   }
        self.widgets.signal_autoconnect(events)

    def close_app(self, source=None, event=None):
        gtk.main_quit()
        sys.exit(0)

        
    def get_active_text(self, combobox):
        """
        Return the text selected in a combobox
        """
        model = combobox.get_model()
        active = combobox.get_active()
        if active < 0:
            return None
        return model[active][0]

    def btn_option_generate_clicked(self, source=None, event=None):
        #modifying the button label during the generation
        self.widgets.get_widget('button-option-generate').set_label('Generating ...')
        try:
            #launch the generation of the SSH key and show a dialog box
            SaveSimplyyourSAN.GenerateRSAKey()
            dialog = gtk.MessageDialog(parent=None, flags=gtk.DIALOG_MODAL, type=gtk.MESSAGE_INFO, buttons=gtk.BUTTONS_OK, message_format=str(RSA_msg))
            dialog.run()
            dialog.destroy()
        except Exception, err:
            #handles possibles errors
            dialog = gtk.MessageDialog(parent=None, flags=gtk.DIALOG_MODAL, type=gtk.MESSAGE_ERROR, buttons=gtk.BUTTONS_CANCEL, message_format=str(err))
            dialog.run()
            dialog.destroy()
        #Set the button's label to its last value
        self.widgets.get_widget('button-option-generate').set_label('Generate !')
        
    def btn_save_start_released(self, source=None, event=None):
        self.widgets.get_widget('label-save-result').set_text('Starting !')
        #get the user's inputs
        ip = self.widgets.get_widget('input-entry-ip').get_text()
        username = self.widgets.get_widget('input-entry-user').get_text()
        password = self.widgets.get_widget('input-entry-pass').get_text()
        #search for the type of switch selected by the user
        if self.widgets.get_widget('radio-brocade').get_active():
            type = 'brocade'
        elif self.widgets.get_widget('radio-cisco').get_active():
            type = 'cisco'
        elif self.widgets.get_widget('radio-mcdata').get_active():
            type = 'mcdata'
        #search for the type of transfert selected by user
        if self.widgets.get_widget('radio-save-SCP').get_active():
            transfert = 'scp'
        elif self.widgets.get_widget('radio-save-FTP').get_active():
            transfert = 'ftp'
        terminal_timeout = self.widgets.get_widget('spinbutton-option-term-timeout').get_value()
        server_timeout = self.widgets.get_widget('spinbutton-option-server-timeout').get_value()
        nat = self.widgets.get_widget('input-entry-save-NAT').get_text()
        directory =''
        ssh_key = ''
        server_interface = self.get_active_text(self.widgets.get_widget('combobox-save-if'))
        if self.widgets.get_widget('radio-save-SSH').get_active():
            client = 'ssh'
        elif self.widgets.get_widget('radio-save-telnet').get_active():
            client = 'telnet'
        switch = SaveSimplyyourSAN.Switch(ip, type, username, password, client, transfert, float(terminal_timeout), server_interface, nat, directory, ssh_key)
        return True
        
    def btn_exec_start_released(self, source=None, event=None):
        self.widgets.get_widget('label-exec-result').set_text('Starting !')
        #get the user's inputs
        ip = self.widgets.get_widget('input-entry-ip').get_text()
        username = self.widgets.get_widget('input-entry-user').get_text()
        password = self.widgets.get_widget('input-entry-pass').get_text()
        #search for the type of switch selected by the user
        if self.widgets.get_widget('radio-brocade').get_active():
            type = 'brocade'
        elif self.widgets.get_widget('radio-cisco').get_active():
            type = 'cisco'
        elif self.widgets.get_widget('radio-mcdata').get_active():
            type = 'mcdata'
        #search for the type of connection selected by user
        if self.widgets.get_widget('radio-exec-SSH').get_active():
            client = 'ssh'
        elif self.widgets.get_widget('radio-exec-telnet').get_active():
            client = 'telnet'
        terminal_timeout = self.widgets.get_widget('spinbutton-option-term-timeout').get_value()
        server_timeout = self.widgets.get_widget('spinbutton-option-server-timeout').get_value()
        #initialize some required values
        nat = ''
        directory =''
        ssh_key = ''
        transfert = 'scp'
        server_interface = ''

        switch = SaveSimplyyourSAN.Switch(ip, type, username, password, client, transfert, float(terminal_timeout), server_interface, nat, directory, ssh_key)
        return True
        
    def check_term_toggled(self, source=None, event=None):
        if self.widgets.get_widget('check-term').get_active():
            self.terminal_output = True
        else:
            self.terminal_output = False
    def radio_mcdata_toggled(self, source=None, event=None):
        #enable and disable some widgets of the GUI
        self.widgets.get_widget('radio-save-http').set_sensitive(True)
        self.widgets.get_widget('radio-save-SSH').set_sensitive(False)
        self.widgets.get_widget('radio-save-telnet').set_sensitive(False)
        self.widgets.get_widget('radio-save-SCP').set_sensitive(False)
        self.widgets.get_widget('radio-save-FTP').set_sensitive(False)
        self.widgets.get_widget('combobox-save-if').set_sensitive(False)
        self.widgets.get_widget('input-entry-save-NAT').set_sensitive(False)
        return True
        

    def radio_cisco_toggled(self, source=None, event=None):
        #enable and disable some widgets of the GUI
        self.widgets.get_widget('radio-save-http').set_sensitive(False)
        self.widgets.get_widget('radio-save-SSH').set_sensitive(True)
        self.widgets.get_widget('radio-save-telnet').set_sensitive(True)
        self.widgets.get_widget('radio-save-SCP').set_sensitive(True)
        self.widgets.get_widget('radio-save-FTP').set_sensitive(True)
        self.widgets.get_widget('combobox-save-if').set_sensitive(True)
        self.widgets.get_widget('input-entry-save-NAT').set_sensitive(True)
        return True
        
    def radio_brocade_toggled(self, source=None, event=None):
        self.radio_cisco_toggled()
        return True
        
    def error_dialog(self, error):
        """
        A dialog box for error messages handling
        """
        dialog = gtk.MessageDialog(parent=None, flags=gtk.DIALOG_MODAL, type=gtk.MESSAGE_ERROR, buttons=gtk.BUTTONS_CANCEL, message_format=str(error))
        # gtk.Dialog.run() does a mini loop to wait
        dialog.run()
        dialog.destroy()

#Launch the GUI
GUI_output = GUI_App()
try:
    app = GUI_output
    gtk.main()
except Exception, err:
    GUI_output.error_dialog(err)