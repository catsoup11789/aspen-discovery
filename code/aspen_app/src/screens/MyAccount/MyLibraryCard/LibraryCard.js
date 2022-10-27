import React, {Component} from "react";
import AsyncStorage from '@react-native-async-storage/async-storage';
import {Center, Flex, Image, Text} from "native-base";
import Barcode from "react-native-barcode-expo";
import Constants from 'expo-constants';
import _ from "lodash";
import moment from "moment";

// custom components and helper files
import {userContext} from "../../../context/user";
import {translate} from '../../../translations/translations';
import {loadingSpinner} from "../../../components/loadingSpinner";
import {loadError} from "../../../components/loadError";

export default class LibraryCard extends Component {
	constructor(props) {
		super(props);
		this.state = {
			isLoading: true,
			hasError: false,
			error: null,
			barcodeStyleInvalid: false,
			user: {
				displayName: "",
				cat_username: "0",
				expires: ""
			},
			library: {
				barcodeStyle: "CODE128",
			},
			location: {
				name: "",
			},
		};
	}

	// store the values into the state
	componentDidMount = async () => {
		this.setState({
			isLoading: false,
		});
	};


	invalidFormat = () => {
		this.setState({
			barcodeStyleInvalid: true,
		});
	};

	static contextType = userContext;

	render() {
		const user = this.context.user;
		const location = this.context.location;
		const library = this.context.library;

		let barcodeStyle = _.toString(library.barcodeStyle);

		let doesNotExpire = false;
		let isExpired = false;
		if(user.expired === 0) {
			const now = moment().format("MMM D, YYYY");
			if(user.expires){
				let dateExpiresOn = moment(_.toString(user.expires));
				isExpired = moment(dateExpiresOn).isBefore(now);
			}

			if(isExpired) {
				doesNotExpire = true;
			}
		}

		let icon;
		if(library.logoApp) {
			icon = library.logoApp;
		} else {
			icon = library.favicon;
		}

		let barcodeValue = "UNKNOWN";
		if(user.cat_username) {
			barcodeValue = user.cat_username;
		}

		if (this.state.isLoading || user.cat_username === "") {
			return (loadingSpinner());
		}

		if (this.state.hasError) {
			return (loadError(this.state.error));
		}

		if(_.isNull(barcodeStyle) || this.state.barcodeStyleInvalid) {
			return (
				<Center flex={1} px={3}>
					<Flex direction="column" bg="white" maxW="90%" px={8} py={5} borderRadius={20}>
						<Center>
							<Flex direction="row">
								<Image
									source={{uri: icon}}
									fallbackSource={require("../../../themes/default/aspenLogo.png")}
									w={42} h={42} alt={translate('user_profile.library_card')}/>
								<Text bold ml={3} mt={2} fontSize="lg" color="darkText">
									{library.displayName}
								</Text>
							</Flex>
						</Center>
						<Center pt={8}>
							<Text pb={2} color="darkText">{user.displayName}</Text>
							<Text color="darkText" bold fontSize="xl">{user.cat_username}</Text>
							{user.expires && !doesNotExpire ? (<Text color="darkText" fontSize={10}>Expires on {user.expires}</Text>) : null}
						</Center>
					</Flex>
				</Center>
			)
		}

		return (
			<Center flex={1} px={3}>
				<Flex direction="column" bg="white" maxW="95%" px={8} py={5} borderRadius={20}>
					<Center>
						<Flex direction="row">
							<Image
								source={{uri: icon}}
								fallbackSource={require("../../../themes/default/aspenLogo.png")}
								w={42} h={42} alt={translate('user_profile.library_card')}/>
							<Text bold ml={3} mt={2} fontSize="lg" color="darkText">
								{library.displayName}
							</Text>
						</Flex>
					</Center>
					<Center pt={8}>
						<Barcode value={barcodeValue} format={barcodeStyle}
						         text={barcodeValue} background="warmGray.100" onError={() => this.invalidFormat()}/>
						{user.expires && !doesNotExpire ? (<Text color="darkText" fontSize={10} pt={2}>Expires on {user.expires}</Text>) : null}
					</Center>
				</Flex>
			</Center>
		);
	}
}
