import React, {Component} from "react";
import {Center, VStack, Spinner, Heading} from "native-base";
import _ from "lodash";
import {userContext} from "../../context/user";

class LoadingScreen extends Component {
	constructor() {
		super();
		this.state = {
			isLoading: true,
		}
	}

	componentDidMount = async () => {

		if (!this.state.isLoading) {
			this.props.navigation.replace('Home');
		}

	}

	checkContext = () => {
		this.setState({
			isLoading: false,
		})
	}

	static contextType = userContext;

	render() {

		const user = this.context.user;
		const location = this.context.location;
		const library = this.context.library;
		const browseCategories = this.context.browseCategories;

		if(_.isEmpty(user) || _.isEmpty(location) || _.isEmpty(library) || _.isEmpty(browseCategories)) {
			return (
				<Center flex={1} px="3">
					<VStack space={5} alignItems="center">
						<Spinner size="lg" />
						<Heading color="primary.500" fontSize="md">
							Dusting the shelves...
						</Heading>
					</VStack>
				</Center>
			)
		} else {
			this.props.navigation.navigate('Tabs');
		}

		return null;
	}
}

export default LoadingScreen;
