/*
 * Free IBM WebSphere Application Server Parser v0.01
 * Copyleft - 2014  Javier Dominguez Gomez
 * Written by Javier Dominguez Gomez <jdg@member.fsf.org>
 * GnuPG Key: 6ECD1616
 * Madrid, Spain
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Ext. lib:    libxml2
 *
 * Compilation: gcc -std=gnu99 -I/usr/include/libxml -O0 -g3 -Wall -c -MMD -MP -MF"fiwasp.d" -MT"fiwasp.d" -o "fiwasp.o" "fiwasp.c"
 *
 * Usage:       ./fiwasp [-m mode|-f file.xml|-h]
 *
 * Examples:  	./fiwasp -f /path/to/file/serverindex.xml
 *              ./fiwasp -m processDefinitions -f /path/to/file/server.xml
 *              ./fiwasp -h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <libxml/parser.h>

const float version = 0.01;
char help(), helpOptMode(), helpServerXmlOptMode(), helpResourcesXmlOptMode(), helpOptFile();
int line(), fileExist(), serverIndexXml(), serverXml(), virtualhostXml(), variablesXml(), resourcesXml();

int main(int argc, char **argv) {
	char *mode = NULL;
	char *file = NULL;
	int index;
	int c;
	opterr = 0;
	while ((c = getopt(argc, argv, "hcm:f:")) != -1)
		switch (c) {
		case 'h':
			help(argv[0]);
			break;
		case 'm':
			mode = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case '?':
			if ((optopt == 'f') || (optopt == 'm'))
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option '-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character '\\x%x'.\n", optopt);
			return 1;
		default:
			abort();
		}
	if (argc == 1){
		printf("No options recive.\n");
		return 1;
	}

	if ((mode) && (!file)){
		fprintf(stderr, "Option '-m' requires '-f' option.\n");
		return 1;
	}

	if (file){
		//if file does not exist exit with error
		if (!fileExist(file)) {
			printf("File '%s' does not exist.\n", file);
			return 1;
		}

		if (strstr(file, "serverindex.xml") != NULL) {
			serverIndexXml(file);
		} else if (strstr(file, "server.xml") != NULL) {
			if (mode){
				if ((!strcmp(mode, "services"))
					|| (!strcmp(mode, "streamRedirect"))
					|| (!strcmp(mode, "components"))
					|| (!strcmp(mode, "processDefinitions"))
					|| (!strcmp(mode, "all")) != '\0') {
					serverXml(file, mode);
				} else {
					helpOptMode();
					helpServerXmlOptMode();
					return 1;
				}
			} else {
				serverXml(file, "processDefinitions");
			}
		} else if (strstr(file, "virtualhosts.xml") != NULL) {
			virtualhostXml(file);
		} else if (strstr(file, "variables.xml") != NULL) {
			variablesXml(file);
		} else if (strstr(file, "resources.xml") != NULL) {
			if (mode){
				if ((!strcmp(mode, "datasources"))
					|| (!strcmp(mode, "queues"))
					|| (!strcmp(mode, "topics"))
					|| (!strcmp(mode, "connFactories"))
					|| (!strcmp(mode, "queueConnFactories"))
					|| (!strcmp(mode, "topicConnFactories"))
					|| (!strcmp(mode, "urls"))
					|| (!strcmp(mode, "all")) != '\0') {
					resourcesXml(file, mode);
				} else {
					helpOptMode();
					helpResourcesXmlOptMode();
					return 1;
				}
			} else {
				resourcesXml(file, "datasources");
			}
		} else {
			printf("Unknown file '%s'.\n", file);
			return 1;
		}
	}
	for (index = optind; index < argc; index++)
		printf("Non-option argument %s\n", argv[index]);
	return 0;
}

int fURLProvider(int count, xmlNode *node){
	for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
		//urls
		if (!xmlStrcmp(attr->name, (const xmlChar *) "name")) {
			count++;
			xmlChar *name = xmlNodeListGetString(node->doc, attr->children, 1);
			line(97);
			fprintf(stdout, "| (%1.2d) %-30.30s %-60.60s |\n", count, "URL", name);
			line(97);
		}
		if ((xmlStrcmp(attr->name, (const xmlChar *) "id"))
				&& (xmlStrcmp(attr->name, (const xmlChar *) "name"))) {
			xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
			fprintf(stdout, "| %-35.35s %-60.60s |\n", attr->name, value);
		}
	}
	line(97);
	return 0;
}

int fJMSProviders(char *typeValue, char *headerName, int count, xmlNode *node, xmlNode *first_child2, xmlNode *node2){
	first_child2 = node->children;
	for (node2 = first_child2; node2; node2 = node2->next) {
		if (node2->type == 1) {
			if (!xmlStrcmp(node2->name,(const xmlChar *) "factories")) {
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					if (!xmlStrcmp(attr->name, (const xmlChar *) "type")) {
						xmlChar *value = xmlNodeListGetString(node2->doc, attr->children, 1);
						//queues
						if (!xmlStrcmp(value, (const xmlChar *) typeValue)) {
							for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
								if (!xmlStrcmp(attr->name, (const xmlChar *) "name")) {
									count++;
									xmlChar *name = xmlNodeListGetString(node2->doc, attr->children, 1);
									line(97);
									fprintf(stdout, "| (%1.2d) %-30.30s %-60.60s |\n", count, headerName, name);
									line(97);
								}
								if ((xmlStrcmp(attr->name, (const xmlChar *) "id"))
										&& (xmlStrcmp(attr->name, (const xmlChar *) "type"))
										&& (xmlStrcmp(attr->name, (const xmlChar *) "name"))) {
									xmlChar *value = xmlNodeListGetString(node2->doc, attr->children, 1);
									fprintf(stdout, "| %-35.35s %-60.60s |\n", attr->name, value);
								}
							}
							line(97);
						}
					}
				}
			}
		}
	}
	return 0;
}

int fJDBCProviders(int count, xmlNode *node, xmlNode *first_child2, xmlNode *node2, xmlNode *first_child3, xmlNode *node3, xmlNode *first_child4, xmlNode *node4){
	for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
		if (!xmlStrcmp(attr->name, (const xmlChar *) "providerType")) {
			first_child2 = node->children;
			for (node2 = first_child2; node2; node2 = node2->next) {
				if (node2->type == 1) {
					//datasources
					if (!xmlStrcmp(node2->name,(const xmlChar *) "factories")) {
						for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
							if (!xmlStrcmp(attr->name, (const xmlChar *) "name")) {
								count++;
								xmlChar *name = xmlNodeListGetString(node2->doc, attr->children, 1);
								line(97);
								fprintf(stdout, "| (%1.2d) %-30.30s %-60.60s |\n", count, "Datasource", name);
								line(97);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "providerType")) {
								xmlChar *providerType = xmlNodeListGetString(node->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "JDBC Provider", providerType);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "jndiName")) {
								xmlChar *jndiName = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "JNDI Name", jndiName);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "description")) {
								xmlChar *description = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "Description", description);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "authMechanismPreference")) {
								xmlChar *authMechanismPreference = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "Auth mechanism pref.", authMechanismPreference);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "authDataAlias")) {
								xmlChar *authDataAlias = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "Auth data alias", authDataAlias);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "manageCachedHandles")) {
								xmlChar *manageCachedHandles = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "Manage cache handles", manageCachedHandles);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "logMissingTransactionContext")) {
								xmlChar *logMissingTransactionContext = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "Log missing trans. context", logMissingTransactionContext);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "diagnoseConnectionUsage")) {
								xmlChar *diagnoseConnectionUsage = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "Diagnose conn. usage", diagnoseConnectionUsage);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "relationalResourceAdapter")) {
								xmlChar *relationalResourceAdapter = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "Relational resource adapter", relationalResourceAdapter);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "statementCacheSize")) {
								xmlChar *statementCacheSize = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "Statement cache size", statementCacheSize);
							}
							if (!xmlStrcmp(attr->name, (const xmlChar *) "datasourceHelperClassname")) {
								xmlChar *datasourceHelperClassname = xmlNodeListGetString(node2->doc, attr->children, 1);
								fprintf(stdout, "| %-35.35s %-60.60s |\n", "DS helper class", datasourceHelperClassname);
							}
						}
						first_child3 = node2->children;
						for (node3 = first_child3; node3; node3 = node3->next) {
							if (node3->type == 1) {
								if (!xmlStrcmp(node3->name,(const xmlChar *) "propertySet")) {
									first_child4 = node3->children;
									for (node4 = first_child4; node4; node4 = node4->next) {
										if (node4->type == 1) {
											if (!xmlStrcmp(node4->name,(const xmlChar *) "resourceProperties")) {
												for (xmlAttrPtr attr = node4->properties; NULL != attr; attr = attr->next) {
													if (!xmlStrcmp(attr->name, (const xmlChar *) "name")) {
														xmlChar *dsPropName = xmlNodeListGetString(node4->doc, attr->children, 1);
														fprintf(stdout, "| %-35.35s", dsPropName);
													}
													if (!xmlStrcmp(attr->name, (const xmlChar *) "value")) {
														xmlChar *dsPropValue = xmlNodeListGetString(node4->doc, attr->children, 1);
														fprintf(stdout, " %-60.60s |\n", dsPropValue);
													}
												}
											}
										}
									}
								}
								if (!xmlStrcmp(node3->name,(const xmlChar *) "connectionPool")) {
									for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
										if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
											xmlChar *connectionTimeout = xmlNodeListGetString(node3->doc, attr->children, 1);
											fprintf(stdout, "| %-35.35s %-60.60s |\n", attr->name, connectionTimeout);
										}
									}
								}
							}
						}
						line(97);
					}
				}
			}
		}
	}
	return 0;
}

int resourcesXml(char *arch, char *mode, xmlDoc *document) {
	xmlNode *root, *first_child, *node, *first_child2, *node2, *first_child3, *node3, *first_child4, *node4;
	document = xmlReadFile(arch, NULL, 0);
	root = xmlDocGetRootElement(document);
	first_child = root->children;
	int count = 0;
	for (node = first_child; node; node = node->next) {
		if (node->type == 1) {
			//JDBCProviders - Datasources
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "datasources") != '\0')) {
				if (!xmlStrcmp(node->name, (const xmlChar *) "JDBCProvider")) {
					fJDBCProviders(count, node, first_child2, node2, first_child3, node3, first_child4, node4);
				}
			}

			//JMSProviders - Queues
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "queues") != '\0')) {
				char *typeValue = "resources.jms.mqseries:MQQueue";
				char *headerName = "Queue";
				if (!xmlStrcmp(node->name, (const xmlChar *) "JMSProvider")) {
					fJMSProviders(typeValue, headerName, count, node, first_child2, node2);
				}
			}

			//JMSProviders - Topics
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "topics") != '\0')) {
				char *typeValue = "resources.jms.mqseries:MQTopic";
				char *headerName = "Topic";
				if (!xmlStrcmp(node->name, (const xmlChar *) "JMSProvider")) {
					fJMSProviders(typeValue, headerName, count, node, first_child2, node2);
				}
			}

			//JMSProviders - Connection Factories
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "connFactories") != '\0')) {
				char *typeValue = "resources.jms.mqseries:MQConnectionFactory";
				char *headerName = "Connection Factory";
				if (!xmlStrcmp(node->name, (const xmlChar *) "JMSProvider")) {
					fJMSProviders(typeValue, headerName, count, node, first_child2, node2);
				}
			}

			//JMSProviders - Queue Connection Factories
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "queueConnFactories") != '\0')) {
				char *typeValue = "resources.jms.mqseries:MQQueueConnectionFactory";
				char *headerName = "Queue Connection Factory";
				if (!xmlStrcmp(node->name, (const xmlChar *) "JMSProvider")) {
					fJMSProviders(typeValue, headerName, count, node, first_child2, node2);
				}
			}

			//JMSProviders - Topic Connection Factories
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "topicConnFactories") != '\0')) {
				char *typeValue = "resources.jms.mqseries:MQTopicConnectionFactory";
				char *headerName = "Topic Connection Factory";
				if (!xmlStrcmp(node->name, (const xmlChar *) "JMSProvider")) {
					fJMSProviders(typeValue, headerName, count, node, first_child2, node2);
				}
			}

			//URLProvider
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "urls") != '\0')) {
				if (!xmlStrcmp(node->name, (const xmlChar *) "URLProvider")) {
					fURLProvider(count, node);
				}
			}
		}
	}
	return 0;
}

int variablesXml(char *arch, xmlDoc *document) {
	xmlNode *root, *first_child, *node;
	document = xmlReadFile(arch, NULL, 0);
	root = xmlDocGetRootElement(document);
	first_child = root->children;
	line(135);
	fprintf(stdout, "| %-43.43s %-90.90s |\n", "Variable", "Value");
	line(135);
	for (node = first_child; node; node = node->next) {
		if (node->type == 1) {
			for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
				if (!xmlStrcmp(attr->name, (const xmlChar *) "symbolicName")) {
					xmlChar *symbolicName = xmlNodeListGetString(node->doc, attr->children, 1);
					fprintf(stdout, "| %-43.43s", symbolicName);
				}
				if (!xmlStrcmp(attr->name, (const xmlChar *) "value")) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					fprintf(stdout, " %-90.90s |\n", value);
				}
			}
		}
	}
	line(135);
	return 0;
}

int virtualhostXml(char *arch, xmlDoc *document) {
	xmlNode *root, *first_child, *node, *first_child2, *node2;
	document = xmlReadFile(arch, NULL, 0);
	root = xmlDocGetRootElement(document);
	first_child = root->children;
	line(63);
	fprintf(stdout, "| %-23.23s %-31.31s %-6.6s |\n", "VirtualHost Name", "Hostname", "Port");
	line(63);
	for (node = first_child; node; node = node->next) {
		if (node->type == 1) {
			for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
				if (!xmlStrcmp(attr->name, (const xmlChar *) "name")) {
					xmlChar *name = xmlNodeListGetString(node->doc, attr->children, 1);
					first_child2 = node->children;
					for (node2 = first_child2; node2; node2 = node2->next) {
						if (node2->type == 1) {
							if (!xmlStrcmp(node2->name,(const xmlChar *) "aliases")) {
								xmlAttrPtr portAttr = xmlHasProp(node2, (const xmlChar*)"port");
								for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
									if (!xmlStrcmp(attr->name, (const xmlChar *) "hostname")) {
										xmlChar *hostname = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, "| %-23.23s %-31.31s ", name, hostname);
									}
									if (!xmlStrcmp(attr->name, (const xmlChar *) "port")) {
										xmlChar *port = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, "%-6.6s |\n", port);
									}
								}
								if (portAttr == NULL) {
									fprintf(stdout, "%-6.6s |\n", "80");
								}
							}
						}
					}
				}
			}
		}
	}
	line(63);
	return 0;
}

int fServices(int count, xmlNode *node, xmlNode *first_child2, xmlNode *node2,
		xmlNode *first_child3, xmlNode *node3) {
	printf(" Service %02d:", count);
	for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
		xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
		if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
			if ((xmlStrcmp(attr->name, (const xmlChar *) "remoteAdminProtocol"))) {
				if (xmlStrcmp(attr->name, (const xmlChar *) "localAdminProtocol")) {
					fprintf(stdout, " %s=\"%s\"", attr->name, value);
				}
			}
		}
	}
	fprintf(stdout, "\n");
	first_child2 = node->children;
	int co = 1, pr = 1, in = 1, pl = 1, tc = 1, ch = 1, tp = 1;
	for (node2 = first_child2; node2; node2 = node2->next) {
		if (node2->type == 1) {
			//connectors
			if (!xmlStrcmp(node2->name, (const xmlChar *) "connectors")) {
				int cv = co++;
				fprintf(stdout, " Service %02d, %s %02d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "type")) || (!xmlStrcmp(attr->name, (const xmlChar *) "enable"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");

				first_child3 = node2->children;
				int p1 = 1;
				for (node3 = first_child3; node3; node3 = node3->next) {
					if (node3->type == 1) {
						fprintf(stdout, " Service %02d, %s %02d, %s %02d:", count, node2->name, cv, node3->name, p1++);
						for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
							xmlChar *value = xmlNodeListGetString(node3->doc, attr->children, 1);
							if ((!xmlStrcmp(attr->name, (const xmlChar *) "name")) || (!xmlStrcmp(attr->name, (const xmlChar *) "value"))) {
								fprintf(stdout, " %s=\"%s\"", attr->name, value);
							}
						}
						fprintf(stdout, "\n");
					}
				}

			}

			//pluginConfigService
			if (!xmlStrcmp(node2->name, (const xmlChar *) "pluginConfigService")) {
				fprintf(stdout, " Service %02d, %s:", count, node2->name);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if (!xmlStrcmp(attr->name, (const xmlChar *) "enable")) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//traceLog
			if (!xmlStrcmp(node2->name, (const xmlChar *) "traceLog")) {
				fprintf(stdout, " Service %02d, %s:", count, node2->name);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "fileName"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "rolloverSize"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "maxNumberOfBackupFiles"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//serviceLog
			if (!xmlStrcmp(node2->name, (const xmlChar *) "serviceLog")) {
				fprintf(stdout, " Service %02d, %s:", count, node2->name);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "name"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "size"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "enabled"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//properties
			if (!xmlStrcmp(node2->name, (const xmlChar *) "properties")) {
				int cv = pr++;
				fprintf(stdout, " Service %02d, %s %d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "name")) || (!xmlStrcmp(attr->name, (const xmlChar *) "value"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//interceptors
			if (!xmlStrcmp(node2->name, (const xmlChar *) "interceptors")) {
				int cv = in++;
				fprintf(stdout, " Service %02d, %s %02d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "name")) || (!xmlStrcmp(attr->name, (const xmlChar *) "value"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}
			//plugins
			if (!xmlStrcmp(node2->name, (const xmlChar *) "plugins")) {
				int cv = pl++;
				fprintf(stdout, " Service %02d, %s %02d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "name")) || (!xmlStrcmp(attr->name, (const xmlChar *) "value"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//threadPool
			if (!xmlStrcmp(node2->name, (const xmlChar *) "threadPool")) {
				fprintf(stdout, " Service %02d, %s:", count, node2->name);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "minimumSize"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "maximumSize"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "inactivityTimeout"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "isGrowable"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "name"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}
			//transportChannels
			if (!xmlStrcmp(node2->name, (const xmlChar *) "transportChannels")) {
				int cv = tc++;
				fprintf(stdout, " Service %02d, %s %02d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "type"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "name"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "endPointName"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "discriminationWeight"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "maxOpenConnections"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "inactivityTimeout"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "maximumPersistentRequests"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "keepAlive"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "readTimeout"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "writeTimeout"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "persistentTimeout"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "enableLogging"))
							|| (!xmlStrcmp(attr->name, (const xmlChar *) "writeBufferSize"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
				first_child3 = node2->children;
				int p1 = 1;
				for (node3 = first_child3; node3; node3 = node3->next) {
					if (node3->type == 1) {
						fprintf(stdout, " Service %02d, %s %02d, %s %02d:", count, node2->name, cv, node3->name, p1++);
						for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
							xmlChar *value = xmlNodeListGetString(node3->doc, attr->children, 1);
							if ((!xmlStrcmp(attr->name, (const xmlChar *) "name")) || (!xmlStrcmp(attr->name, (const xmlChar *) "value"))) {
								fprintf(stdout, " %s=\"%s\"", attr->name, value);
							}
						}
						fprintf(stdout, "\n");
					}
				}
			}

			//chains
			if (!xmlStrcmp(node2->name, (const xmlChar *) "chains")) {
				int cv = ch++;
				fprintf(stdout, " Service %02d, %s %02d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "name")) || (!xmlStrcmp(attr->name, (const xmlChar *) "enable"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//threadPools
			if (!xmlStrcmp(node2->name, (const xmlChar *) "threadPools")) {
				int cv = tp++;
				fprintf(stdout, " Service %02d, %s %02d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "minimumSize"))
						|| (!xmlStrcmp(attr->name, (const xmlChar *) "maximumSize"))
						|| (!xmlStrcmp(attr->name, (const xmlChar *) "inactivityTimeout"))
						|| (!xmlStrcmp(attr->name, (const xmlChar *) "isGrowable"))
						|| (!xmlStrcmp(attr->name, (const xmlChar *) "name"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//errorLog & accessLog
			if ((!xmlStrcmp(node2->name, (const xmlChar *) "errorLog")) || (!xmlStrcmp(node2->name, (const xmlChar *) "accessLog"))) {
				fprintf(stdout, " Service %02d, %s:", count, node2->name);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if ((!xmlStrcmp(attr->name, (const xmlChar *) "filePath")) || (!xmlStrcmp(attr->name, (const xmlChar *) "maximumSize"))) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}
		}
	}
	return 0;
}

int fComponents(int count, xmlNode *node, xmlNode *first_child2, xmlNode *node2, xmlNode *first_child3,
		xmlNode *node3, xmlNode *first_child4, xmlNode *node4, xmlNode *first_child5, xmlNode *node5) {
	printf(" Component %02d:", count);
	for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
		xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
		if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
			fprintf(stdout, " %s=\"%s\"", attr->name, value);
		}
	}
	fprintf(stdout, "\n");
	first_child2 = node->children;
	int se = 1;
	int co = 1;
	for (node2 = first_child2; node2; node2 = node2->next) {
		if (node2->type == 1) {
			//stateManagement
			if (!xmlStrcmp(node2->name, (const xmlChar *) "stateManagement")) {
				fprintf(stdout, " Component %02d, %s:", count, node2->name);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if (!xmlStrcmp(attr->name, (const xmlChar *) "initialState")) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//services
			if (!xmlStrcmp(node2->name, (const xmlChar *) "services")) {
				int cv = se++;
				fprintf(stdout, " Component %02d, %s %02d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");

				first_child3 = node2->children;
				for (node3 = first_child3; node3; node3 = node3->next) {
					if (node3->type == 1) {
						//cacheGroups
						fprintf(stdout, " Component %02d, %s %02d, %s:", count, node2->name, cv, node3->name);
						for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
							xmlChar *value = xmlNodeListGetString(node3->doc, attr->children, 1);
							if ((!xmlStrcmp(attr->name, (const xmlChar *) "name"))
									|| (!xmlStrcmp(attr->name, (const xmlChar *) "value"))) {
								fprintf(stdout, " %s=\"%s\"", attr->name, value);
							}
						}
						fprintf(stdout, "\n");

						first_child4 = node3->children;
						for (node4 = first_child4; node4; node4 = node4->next) {
							if (node4->type == 1) {
								//cacheGroups
								fprintf(stdout, " Component %02d, %s %02d, %s, %s:", count, node2->name, cv, node3->name, node4->name);
								for (xmlAttrPtr attr = node4->properties; NULL != attr; attr = attr->next) {
									xmlChar *value = xmlNodeListGetString(node4->doc, attr->children, 1);
									if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
										fprintf(stdout, " %s=\"%s\"", attr->name, value);
									}
								}
								fprintf(stdout, "\n");

							}
						}
					}
				}
			}

			//properties
			if (!xmlStrcmp(node2->name, (const xmlChar *) "properties")) {
				fprintf(stdout, " Component %02d, %s:", count, node2->name);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}

			//components
			if (!xmlStrcmp(node2->name, (const xmlChar *) "components")) {
				int cv = co++;
				fprintf(stdout, " Component %02d, %s %02d:", count, node2->name, cv);
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");

				first_child3 = node2->children;
				int p1 = 1;
				int se1 = 0;
				for (node3 = first_child3; node3; node3 = node3->next) {
					if (node3->type == 1) {
						//stateManagement
						if (!xmlStrcmp(node3->name, (const xmlChar *) "stateManagement")) {
							fprintf(stdout, " Component %02d, %s %02d, %s:", count, node2->name, cv, node3->name);
							for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
								xmlChar *value = xmlNodeListGetString( node3->doc, attr->children, 1);
								if (!xmlStrcmp(attr->name, (const xmlChar *) "initialState")) {
									fprintf(stdout, " %s=\"%s\"", attr->name, value);
								}
							}
							fprintf(stdout, "\n");
						}

						//services
						int se1cv = se1++;
						if (!xmlStrcmp(node3->name, (const xmlChar *) "services")) {
							fprintf(stdout, " Component %02d, %s %02d, %s %02d:", count, node2->name, cv, node3->name, se1cv);
							for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
								xmlChar *value = xmlNodeListGetString(node3->doc, attr->children, 1);
								if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
									fprintf(stdout, " %s=\"%s\"", attr->name, value);
								}
							}
							fprintf(stdout, "\n");
							first_child4 = node3->children;
							for (node4 = first_child4; node4; node4 = node4->next) {
								if (node4->type == 1) {
									//defaultCookieSettings & sessionDatabasePersistence & sessionDRSPersistence & threadPool
									if ((!xmlStrcmp(node4->name, (const xmlChar *) "defaultCookieSettings"))
										|| (!xmlStrcmp(node4->name, (const xmlChar *) "sessionDatabasePersistence"))
										|| (!xmlStrcmp(node4->name, (const xmlChar *) "sessionDRSPersistence"))
										|| (!xmlStrcmp(node4->name, (const xmlChar *) "threadPool"))) {
										fprintf(stdout, " Component %02d, %s %02d, %s %02d, %s:",
												count, node2->name, cv, node3->name, se1cv, node4->name);
										for (xmlAttrPtr attr = node4->properties; NULL != attr; attr = attr->next) {
											xmlChar *value = xmlNodeListGetString(node4->doc, attr->children, 1);
											if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
												fprintf(stdout, " %s=\"%s\"", attr->name, value);
											}
										}
										fprintf(stdout, "\n");
									}

									//tuningParams
									if (!xmlStrcmp(node4->name, (const xmlChar *) "tuningParams")) {
										fprintf(stdout, " Component %02d, %s %02d, %s %02d, %s:",
												count, node2->name, cv, node3->name, se1cv, node4->name);
										for (xmlAttrPtr attr = node4->properties;
										NULL != attr; attr = attr->next) {
											xmlChar *value = xmlNodeListGetString(node4->doc, attr->children, 1);
											if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
												fprintf(stdout, " %s=\"%s\"", attr->name, value);
											}
										}
										fprintf(stdout, "\n");
										first_child5 = node4->children;
										for (node5 = first_child5; node5; node5 = node5->next) {
											if (node5->type == 1) {
												//invalidationSchedule
												if (!xmlStrcmp(node5->name, (const xmlChar *) "invalidationSchedule")) {
													fprintf(stdout, " Component %02d, %s %02d, %s %02d, %s, %s:",
															count, node2->name, cv, node3->name, se1cv, node4->name, node5->name);
													for (xmlAttrPtr attr = node5->properties; NULL != attr; attr = attr->next) {
														xmlChar *value = xmlNodeListGetString(node5->doc, attr->children, 1);
														if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
															fprintf(stdout, " %s=\"%s\"", attr->name, value);
														}
													}
													fprintf(stdout, "\n");
												}
											}
										}
									}
								}
							}
						}

						//properties
						if (!xmlStrcmp(node3->name, (const xmlChar *) "properties")) {
							fprintf(stdout, " Component %02d, %s %02d, %s %02d:",
									count, node2->name, cv, node3->name, p1++);
							for (xmlAttrPtr attr = node3->properties;
							NULL != attr; attr = attr->next) {
								xmlChar *value = xmlNodeListGetString(node3->doc, attr->children, 1);
								if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
									fprintf(stdout, " %s=\"%s\"", attr->name, value);
								}
							}
							fprintf(stdout, "\n");
						}

						//cacheSettings & timerSettings & asyncSettings
						if ((!xmlStrcmp(node3->name, (const xmlChar *) "cacheSettings"))
							|| (!xmlStrcmp(node3->name, (const xmlChar *) "timerSettings"))
							|| (!xmlStrcmp(node3->name, (const xmlChar *) "asyncSettings"))) {
							fprintf(stdout, " Component %02d, %s %02d, %s:", count, node2->name, cv, node3->name);
							for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
								xmlChar *value = xmlNodeListGetString( node3->doc, attr->children, 1);
								if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
									fprintf(stdout, " %s=\"%s\"", attr->name, value);
								}
							}
							fprintf(stdout, "\n");
						}
					}
				}
			}

			//webserverPluginSettings
			if (!xmlStrcmp(node2->name, (const xmlChar *) "webserverPluginSettings")) {
				fprintf(stdout, " WebserverPluginSettings:");
				for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
					xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
					if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
						fprintf(stdout, " %s=\"%s\"", attr->name, value);
					}
				}
				fprintf(stdout, "\n");
			}
		}
	}
	return 0;
}

int fStreamRedirect(xmlNode *node, char *tag) {
	printf(" %s:", tag);
	for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
		xmlChar *value = xmlNodeListGetString(node->doc, attr->children, 1);
		if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
			fprintf(stdout, " %s=\"%s\"", attr->name, value);
		}
	}
	fprintf(stdout, "\n");
	return 0;
}

int serverXml(char *arch, char *mode, xmlDoc *document) {
	xmlNode *root, *first_child, *node, *first_child2, *node2, *first_child3, *node3,
	*first_child4, *node4, *first_child5, *node5;
	document = xmlReadFile(arch, NULL, 0);
	root = xmlDocGetRootElement(document);
	first_child = root->children;
	for (xmlAttrPtr attr = root->properties; NULL != attr; attr = attr->next) {
		if (!xmlStrcmp(attr->name, (const xmlChar *) "name")) {
			xmlChar* name = xmlNodeListGetString(root->doc, attr->children, 1);
			fprintf(stdout, " %s\t\t%s\n", "Server Name:", name);
		}
	}
	int servicesc = 1, componentsc = 1;
	for (node = first_child; node; node = node->next) {
		if (node->type == 1) {
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "services") != '\0')) {
				//services
				if (!xmlStrcmp(node->name, (const xmlChar *) "services")) {
					fServices(servicesc++, node, first_child2, node2, first_child3, node3);
				}
			}
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "streamRedirect") != '\0')) {
				//errorStreamRedirect
				if (!xmlStrcmp(node->name, (const xmlChar *) "errorStreamRedirect")) {
					fStreamRedirect(node, "ErrLog");
				}
				//outputStreamRedirect
				if (!xmlStrcmp(node->name, (const xmlChar *) "outputStreamRedirect")) {
					fStreamRedirect(node, "OutLog");
				}
			}
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "components") != '\0')) {
				//components
				if (!xmlStrcmp(node->name, (const xmlChar *) "components")) {
					fComponents(componentsc++, node, first_child2, node2, first_child3, node3,
							first_child4, node4, first_child5, node5);
				}
			}
			if ((!strcmp(mode, "all")) || (!strcmp(mode, "processDefinitions") != '\0')) {
				//processDefinitions
				if (!xmlStrcmp(node->name, (const xmlChar *) "processDefinitions")) {
					//executableName
					for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
						if (!xmlStrcmp(attr->name, (const xmlChar *) "executableName")) {
							xmlChar *executableName = xmlNodeListGetString(node->doc, attr->children, 1);
							fprintf(stdout, " Executable name:\t%s\n", executableName);
						}
					}
					first_child2 = node->children;
					for (node2 = first_child2; node2; node2 = node2->next) {
						if (node2->type == 1) {
							if (!xmlStrcmp(node2->name, (const xmlChar *) "execution")) {
								for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
									//processPriority
									if (!xmlStrcmp(attr->name, (const xmlChar *) "processPriority")) {
										xmlChar* processPriority = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Process Priority:\t%s\n", processPriority);
									}
									//umask
									if (!xmlStrcmp(attr->name, (const xmlChar *) "umask")) {
										xmlChar* umask = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Umask:\t\t\t%s\n", umask);
									}
									//runAsUser
									if (!xmlStrcmp(attr->name, (const xmlChar *) "runAsUser")) {
										xmlChar* runAsUser = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Run as user:\t\t%s\n", runAsUser);
									}
									//runAsGroup
									if (!xmlStrcmp(attr->name, (const xmlChar *) "runAsGroup")) {
										xmlChar* runAsGroup = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Run as group:\t\t%s\n", runAsGroup);
									}
								}
							}

							//ioRedirect
							if (!xmlStrcmp(node2->name, (const xmlChar *) "ioRedirect")) {
								for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
									//stdoutFilename
									if (!xmlStrcmp(attr->name, (const xmlChar *) "stdoutFilename")) {
										xmlChar* stdoutFilename = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " NativeOut Filename:\t%s\n", stdoutFilename);
									}
									//stderrFilename
									if (!xmlStrcmp(attr->name, (const xmlChar *) "stderrFilename")) {
										xmlChar* stderrFilename = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " NativeErr Filename:\t%s\n", stderrFilename);
									}
								}
							}

							//monitoringPolicy
							if (!xmlStrcmp(node2->name, (const xmlChar *) "monitoringPolicy")) {
								for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
									//maximumStartupAttempts
									if (!xmlStrcmp(attr->name, (const xmlChar *) "maximumStartupAttempts")) {
										xmlChar* maximumStartupAttempts = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Max. Startup Attempts:\t%s\n", maximumStartupAttempts);
									}
									//pingInterval
									if (!xmlStrcmp(attr->name, (const xmlChar *) "pingInterval")) {
										xmlChar* pingInterval = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Ping Interval:\t\t%s\n", pingInterval);
									}
									//pingTimeout
									if (!xmlStrcmp(attr->name, (const xmlChar *) "pingTimeout")) {
										xmlChar* pingTimeout = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Ping Timeout:\t\t%s\n", pingTimeout);
									}
									//autoRestart
									if (!xmlStrcmp(attr->name, (const xmlChar *) "autoRestart")) {
										xmlChar* autoRestart = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Auto Restart:\t\t%s\n", autoRestart);
									}
									//nodeRestartState
									if (!xmlStrcmp(attr->name, (const xmlChar *) "nodeRestartState")) {
										xmlChar* nodeRestartState = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Node Restart State:\t%s\n", nodeRestartState);
									}
								}
							}

							//jvmEntries
							if ((!xmlStrcmp(node2->name, (const xmlChar *) "jvmEntries"))) {
								for (xmlAttrPtr attr = node2->properties; NULL != attr; attr = attr->next) {
									//verboseModeClass
									if (!xmlStrcmp(attr->name, (const xmlChar *) "verboseModeClass")) {
										xmlChar* verboseModeClass = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Verbose Mode Class:\t%s\n", verboseModeClass);
									}

									//verboseModeGarbageCollection
									if (!xmlStrcmp(attr->name, (const xmlChar *) "verboseModeGarbageCollection")) {
										xmlChar* verboseModeGarbageCollection = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Verbose Mode GC:\t%s\n", verboseModeGarbageCollection);
									}

									//verboseModeJNI
									if (!xmlStrcmp(attr->name, (const xmlChar *) "verboseModeJNI")) {
										xmlChar* verboseModeJNI = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Verbose Mode JNI:\t%s\n", verboseModeJNI);
									}

									//initialHeapSize
									if (!xmlStrcmp(attr->name, (const xmlChar *) "initialHeapSize")) {
										xmlChar* initialHeapSize = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Initial Heap Size:\t%s\n", initialHeapSize);
									}

									//maximumHeapSize
									if (!xmlStrcmp(attr->name, (const xmlChar *) "maximumHeapSize")) {
										xmlChar* maximumHeapSize = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Maximum Heap Size:\t%s\n", maximumHeapSize);
									}

									//runHProf
									if (!xmlStrcmp(attr->name, (const xmlChar *) "runHProf")) {
										xmlChar* runHProf = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Run HProf:\t\t%s\n", runHProf);
									}

									//hprofArguments
									if (!xmlStrcmp(attr->name, (const xmlChar *) "hprofArguments")) {
										xmlChar* hprofArguments = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " HProf Arguments:\t%s\n", hprofArguments);
									}

									//debugMode
									if (!xmlStrcmp(attr->name, (const xmlChar *) "debugMode")) {
										xmlChar* debugMode = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Debug Mode:\t\t%s\n", debugMode);
									}

									//debugArgs
									if (!xmlStrcmp(attr->name, (const xmlChar *) "debugArgs")) {
										xmlChar* debugArgs = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Debug Args:\t\t%s\n", debugArgs);
									}

									//genericJvmArguments
									if (!xmlStrcmp(attr->name, (const xmlChar *) "genericJvmArguments")) {
										xmlChar* genericJvmArguments = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Generic Jvm Args.:\t%s\n", genericJvmArguments);
									}

									//executableJarFileName
									if (!xmlStrcmp(attr->name, (const xmlChar *) "executableJarFileName")) {
										xmlChar* executableJarFileName = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Exec. Jar FileName:\t%s\n", executableJarFileName);
									}

									//disableJIT
									if (!xmlStrcmp(attr->name, (const xmlChar *) "disableJIT")) {
										xmlChar* disableJIT = xmlNodeListGetString(node2->doc, attr->children, 1);
										fprintf(stdout, " Disable JIT:\t\t%s\n", disableJIT);
									}
								}

								//Properties
								first_child3 = node2->children;
								int node3c = 1;
								for (node3 = first_child3; node3; node3 = node3->next) {
									if (node3->type == 1) {
										fprintf(stdout, " Custom Propertie %d:", node3c++);
										for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
											if (xmlStrcmp(attr->name, (const xmlChar *) "id")) {
												xmlChar* value = xmlNodeListGetString(node3->doc, attr->children, 1);
												fprintf(stdout, "\t%s=\"%s\"", attr->name, value);
											}
										}
										fprintf(stdout, "\n");
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}

int serverIndexXml(char *arch, xmlDoc *document) {
	xmlNode *root, *first_child, *node, *first_child2, *node2, *first_child3, *node3, *first_child4, *node4;
	document = xmlReadFile(arch, NULL, 0);
	root = xmlDocGetRootElement(document);
	first_child = root->children;
	struct utsname unameData;
	uname(&unameData);
	line(139);
	fprintf(stdout, "| %-10.10s %-7.7s %-24.24s %-27.27s %-17.17s %-9.9s %-38.38s |\n",
			"Host", "OS", "JVM", "Application", "Host", "Port", "Port name");
	line(139);
	for (xmlAttrPtr attr = root->properties; NULL != attr; attr = attr->next) {
		if (!xmlStrcmp(attr->name, (const xmlChar *) "hostName")) {
			xmlChar* hostName = xmlNodeListGetString(root->doc, attr->children, 1);
			for (node = first_child; node; node = node->next) {
				if (node->type == 1) {
					for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
						if (!xmlStrcmp(attr->name, (const xmlChar *) "serverName")) {
							xmlChar* jvmName = xmlNodeListGetString(node->doc, attr->children, 1);
							first_child2 = node->children;
							if ((!xmlStrncmp(jvmName, (const xmlChar *) "dmgr", 4)) || (!xmlStrncmp(jvmName, (const xmlChar *) "nodeagent", 9))) {
								for (node3 = first_child2; node3; node3 = node3->next) {
									if (node3->type == 1) {
										if (!xmlStrcmp(node3->name, (const xmlChar *) "specialEndpoints")) {
											for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
												if (!xmlStrcmp(attr->name, (const xmlChar *) "endPointName")) {
													xmlChar* endPointName = xmlNodeListGetString(node3->doc, attr->children, 1);
													fprintf(stdout, "| %-10.10s %-7.7s %-24.24s %-27.27s", hostName, unameData.sysname, jvmName, "-");
													first_child4 = node3->children;
													for (node4 = first_child4; node4; node4 = node4->next) {
														if (node4->type == 1) {
															for (xmlAttrPtr attr = node4->properties; NULL != attr; attr = attr->next) {
																if (!xmlStrcmp(attr->name, (const xmlChar *) "host")) {
																	xmlChar* host = xmlNodeListGetString(node4->doc, attr->children, 1);
																	fprintf(stdout, " %-17.17s ", host);
																}
																if (!xmlStrcmp(attr->name, (const xmlChar *) "port")) {
																	xmlChar* port = xmlNodeListGetString(node4->doc, attr->children, 1);
																	fprintf(stdout, "%-9.9s ", port);
																}
															}
														}
													}
													fprintf(stdout, "%-38.38s |\n", endPointName);
												}
											}
										}
									}
								}
							}
							for (node2 = first_child2; node2; node2 = node2->next) {
								if (node2->type == 1) {
									if (!xmlStrcmp(node2->name, (const xmlChar *) "deployedApplications")) {
										xmlChar* app = xmlNodeListGetString(node2->doc, node2->xmlChildrenNode, 1);
										if ((xmlStrncmp(app, (const xmlChar *) "commsvc", 7))
											&& (xmlStrncmp(app, (const xmlChar *) "ibmasyncrsp", 11))
											&& (xmlStrncmp(app, (const xmlChar *) "WebSphereWSDM", 13))
											&& (xmlStrncmp(app, (const xmlChar *) "OTiS", 4))) {
											char *ear;
											ear = strtok(app, "/");
											for (xmlAttrPtr attr = node->properties; NULL != attr; attr = attr->next) {
												if (!xmlStrcmp(attr->name, (const xmlChar *) "serverName")) {
													first_child3 = node->children;
													for (node3 = first_child2; node3; node3 = node3->next) {
														if (node3->type == 1) {
															if (!xmlStrcmp(node3->name, (const xmlChar *) "specialEndpoints")) {
																for (xmlAttrPtr attr = node3->properties; NULL != attr; attr = attr->next) {
																	if (!xmlStrcmp(attr->name, (const xmlChar *) "endPointName")) {
																		xmlChar* endPointName = xmlNodeListGetString(node3->doc, attr->children, 1);
																		fprintf(stdout, "| %-10.10s %-7.7s %-24.24s %-27.27s",
																				hostName, unameData.sysname, jvmName, ear);
																		first_child4 = node3->children;
																		for (node4 = first_child4; node4; node4 = node4->next) {
																			if (node4->type == 1) {
																				for (xmlAttrPtr attr = node4->properties; NULL != attr; attr = attr->next) {
																					xmlChar* hostAndPort = xmlNodeListGetString(node4->doc, attr->children, 1);
																					if (!xmlStrcmp(attr->name, (const xmlChar *) "host")) {
																						fprintf(stdout, " %-17.17s ", hostAndPort);
																					}
																					if (!xmlStrcmp(attr->name, (const xmlChar *) "port")) {
																						fprintf(stdout, "%-9.9s ", hostAndPort);
																					}
																				}
																			}
																		}
																		fprintf(stdout, "%-38.38s |\n", endPointName);
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	line(139);
	return 0;
}

char help(char *bin) {
	printf("\n   HELP\n\tDescription:\tFree IBM WebSphere Application Server Parser v%1.2f\n"
	"\t\t\tThis program is free software: you can redistribute it and/or modify it under the terms of the\n"
	"\t\t\tGNU General Public License as published by the Free Software Foundation, either version 3 of\n"
	"\t\t\tthe License, or (at your option) any later version.\n\n"
	"\tUsage:\t\t%s [-m mode|-f file.xml|-h]\n\n"
	"\tExample:\t%s -m processDefinitions -f /path/to/file/server.xml\n",version, bin, bin);
	helpOptMode();
	helpServerXmlOptMode();
	helpResourcesXmlOptMode();
	helpOptFile();
	printf("\t\t\t-h\tThis help.\n\n");
	return 0;
}

char helpOptFile() {
	printf("\t\t\t-f\tFile XML input. These are the valid files to print information:\n\n"
		"\t\t\t\tresources.xml\t\tContains all resources information, like datasources, topics, queues,\n"
		"\t\t\t\t\t\t\tconnection factories, resource adapters, JMS or JDBC providers, etc.\n"
		"\t\t\t\tserver.xml\t\tContains all JVM settings.\n"
		"\t\t\t\tserverindex.xml\t\tContains all the servers ports information.\n"
		"\t\t\t\tvariables.xml\t\tContains all WebSphere variables settings.\n"
		"\t\t\t\tvirtualhosts.xml\tContains all host aliases to a single hostname.\n\n");
	return 0;
}

char helpResourcesXmlOptMode() {
	printf("\n\t\t\t\tFor resources.xml file\n"
		"\t\t\t\t----------------------\n"
		"\t\t\t\tThe following options are valid:\n\n"
		"\t\t\t\tdatasources\t\tPrint JDBC 'Datasources' block information form resources.xml.\n"
		"\t\t\t\tqueues\t\t\tPrint JMS 'Queues' block information form resources.xml.\n"
		"\t\t\t\ttopics\t\t\tPrint JMS 'Topics' block information form resources.xml.\n"
		"\t\t\t\tconnFactories\t\tPrint JMS 'Connection Factories' block information form resources.xml.\n"
		"\t\t\t\tqueueConnFactories\tPrint JMS 'Queue Connection Factories' block information form resources.xml.\n"
		"\t\t\t\ttopicConnFactories\tPrint JMS 'Topic Connection Factories' block information form resources.xml.\n"
		"\t\t\t\tall\t\t\tPrint all information form resources.xml.\n\n"
		"\t\t\t\tIf the -m option is not specified the program prints 'Datasources' block\n"
		"\t\t\t\tinformation by default.\n\n");
	return 0;
}

char helpServerXmlOptMode() {
	printf("\n\t\t\t\tFor server.xml file\n"
		"\t\t\t\t-------------------\n"
		"\t\t\t\tThe following options are valid:\n\n"
		"\t\t\t\tstreamRedirect\t\tPrint 'streamRedirect' block information form server.xml.\n"
		"\t\t\t\tcomponents\t\tPrint 'components' block information form server.xml.\n"
		"\t\t\t\tprocessDefinitions\tPrint 'processDefinitions' block information form server.xml.\n"
		"\t\t\t\tall\t\t\tPrint all information form server.xml.\n\n"
		"\t\t\t\tIf the -m option is not specified the program prints 'processDefinitions' block\n"
		"\t\t\t\tinformation by default.\n\n");
	return 0;
}

char helpOptMode() {
	printf("\n\tOptions:\t-m\t(Optional) This option specifies a fragment or full information.\n");
	return 0;
}

int fileExist(const char* filePath) {
	FILE *checkFile = fopen(filePath, "r");
	if (checkFile) {
		fclose(checkFile);
		return 1; //TRUE
	} else {
		return 0; //FALSE
	}
}

int line(int s) {
	printf("+");
	for (int i = 0; i <= s; i++) {
		printf("-");
	}
	printf("+\n");
	return 0;
}
